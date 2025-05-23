// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/new-spaces.h"

#include <atomic>
#include <optional>

#include "src/common/globals.h"
#include "src/flags/flags.h"
#include "src/heap/allocation-observer.h"
#include "src/heap/array-buffer-sweeper.h"
#include "src/heap/concurrent-marking.h"
#include "src/heap/free-list-inl.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-verifier.h"
#include "src/heap/incremental-marking.h"
#include "src/heap/mark-compact.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/marking-state.h"
#include "src/heap/memory-allocator.h"
#include "src/heap/memory-chunk.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/page-metadata-inl.h"
#include "src/heap/page-metadata.h"
#include "src/heap/paged-spaces.h"
#include "src/heap/safepoint.h"
#include "src/heap/spaces-inl.h"
#include "src/heap/spaces.h"
#include "src/heap/zapping.h"

namespace v8 {
namespace internal {

// -----------------------------------------------------------------------------
// SemiSpace implementation

PageMetadata* SemiSpace::InitializePage(MutablePageMetadata* mutable_page) {
  bool in_to_space = (id() != kFromSpace);
  MemoryChunk* chunk = mutable_page->Chunk();
  chunk->SetFlagNonExecutable(in_to_space ? MemoryChunk::TO_PAGE
                                          : MemoryChunk::FROM_PAGE);
  PageMetadata* page = PageMetadata::cast(mutable_page);
  page->list_node().Initialize();
  CHECK(page->IsLivenessClear());
  chunk->InitializationMemoryFence();
  return page;
}

bool SemiSpace::EnsureCurrentCapacity() {
  if (IsCommitted()) {
    EnsureCapacity(target_capacity_);
  }
  allow_to_grow_beyond_capacity_ = false;
  return true;
}

SemiSpace::~SemiSpace() {
  // Properly uncommit memory to keep the allocator counters in sync.
  if (IsCommitted()) {
    Uncommit();
  }
}

bool SemiSpace::EnsureCapacity(size_t capacity) {
  DCHECK_IMPLIES(!IsCommitted(), CommittedMemory() == 0);
  const size_t quarantined_pages =
      id_ == kToSpace ? quarantined_pages_count_ : 0;
  const int num_pages =
      static_cast<int>((capacity / PageMetadata::kPageSize) -
                       memory_chunk_list_.size() - quarantined_pages);
  if (num_pages >= 0) {
    for (int pages_added = 0; pages_added < num_pages; pages_added++) {
      if (!AllocateFreshPage()) {
        if (pages_added) RewindPages(pages_added);
        return false;
      }
    }
  } else {
    // Due to previously quarantined pages, we already have more pages then
    // needed. Free the redundant pages.
    RewindPages(-num_pages);
  }
  DCHECK_EQ(capacity + quarantined_pages * PageMetadata::kPageSize,
            CommittedMemory());
  DCHECK_EQ(
      static_cast<int>(capacity / PageMetadata::kPageSize) + quarantined_pages,
      memory_chunk_list_.size());
  return true;
}

bool SemiSpace::Commit() {
  if (!EnsureCapacity(target_capacity_)) {
    return false;
  }
  Reset();
  DCHECK_EQ(target_capacity_, CommittedMemory());
  if (age_mark_ == kNullAddress) {
    age_mark_ = first_page()->area_start();
  }
  DCHECK(IsCommitted());
  return true;
}

void SemiSpace::Uncommit() {
  DCHECK(IsCommitted());
  DCHECK_EQ(CommittedMemory(),
            memory_chunk_list_.size() * PageMetadata::kPageSize);
  RewindPages(static_cast<int>(memory_chunk_list_.size()));
  current_page_ = nullptr;
  current_capacity_ = 0;
  quarantined_pages_count_ = 0;
  DCHECK_EQ(CommittedPhysicalMemory(), 0);
  DCHECK_EQ(CommittedMemory(), 0);
  DCHECK(!IsCommitted());
}

size_t SemiSpace::CommittedPhysicalMemory() const {
  if (!IsCommitted()) return 0;
  if (!base::OS::HasLazyCommits()) return CommittedMemory();
  return committed_physical_memory_;
}

bool SemiSpace::GrowTo(size_t new_capacity) {
  if (!IsCommitted()) {
    if (!Commit()) {
      DCHECK(!IsCommitted());
      return false;
    }
  }
  DCHECK(MemoryChunk::IsAligned(new_capacity));
  DCHECK_LE(new_capacity, maximum_capacity_);
  DCHECK_GT(new_capacity, target_capacity_);
  if (!EnsureCapacity(new_capacity)) {
    return false;
  }
  target_capacity_ = new_capacity;
  return true;
}

bool SemiSpace::AllocateFreshPage() {
  PageMetadata* new_page = heap()->memory_allocator()->AllocatePage(
      MemoryAllocator::AllocationMode::kUsePool, this, NOT_EXECUTABLE);
  if (new_page == nullptr) {
    return false;
  }
  memory_chunk_list_.PushBack(new_page);
  IncrementCommittedPhysicalMemory(new_page->CommittedPhysicalMemory());
  AccountCommitted(PageMetadata::kPageSize);
  heap()->CreateFillerObjectAt(new_page->area_start(),
                               static_cast<int>(new_page->area_size()));
  return true;
}

void SemiSpace::RewindPages(int num_pages) {
  DCHECK_GT(num_pages, 0);
  DCHECK(last_page());
  AccountUncommitted(num_pages * PageMetadata::kPageSize);
  size_t uncommitted_physical_memory = 0;
  while (num_pages > 0) {
    MutablePageMetadata* last = last_page();
    CHECK_NOT_NULL(last);
    uncommitted_physical_memory += last->CommittedPhysicalMemory();
    memory_chunk_list_.Remove(last);
    heap()->memory_allocator()->Free(MemoryAllocator::FreeMode::kPool, last);
    num_pages--;
  }
  DecrementCommittedPhysicalMemory(uncommitted_physical_memory);
}

void SemiSpace::ShrinkTo(size_t new_capacity) {
  DCHECK(MemoryChunk::IsAligned(new_capacity));
  DCHECK_GE(new_capacity, minimum_capacity_);
  DCHECK_LT(new_capacity, target_capacity_);
  if (IsCommitted()) {
    EnsureCapacity(new_capacity);
  }
  target_capacity_ = new_capacity;
}

void SemiSpace::FixPagesFlags() {
  const auto to_space_flags =
      MemoryChunk::YoungGenerationPageFlags(
          heap()->incremental_marking()->marking_mode()) |
      MemoryChunk::TO_PAGE;
  for (PageMetadata* page : *this) {
    MemoryChunk* chunk = page->Chunk();
    page->set_owner(this);
    if (id_ == kToSpace) {
      chunk->SetFlagsNonExecutable(to_space_flags);
    } else {
      DCHECK_EQ(id_, kFromSpace);
      // From space must preserve `NEW_SPACE_BELOW_AGE_MARK` which is used for
      // deciding on whether to copy or promote an object.
      chunk->SetFlagNonExecutable(MemoryChunk::FROM_PAGE);
      chunk->ClearFlagNonExecutable(MemoryChunk::TO_PAGE);
    }
    DCHECK(chunk->InYoungGeneration());
  }
}

void SemiSpace::Reset() {
  DCHECK(first_page());
  DCHECK(last_page());
  current_page_ = first_page();
  current_capacity_ = PageMetadata::kPageSize;
  quarantined_pages_count_ = 0;
}

void SemiSpace::RemovePage(PageMetadata* page) {
  if (current_page_ == page) {
    if (page->prev_page()) {
      current_page_ = page->prev_page();
    }
  }
  memory_chunk_list_.Remove(page);
  AccountUncommitted(PageMetadata::kPageSize);
  DecrementCommittedPhysicalMemory(page->CommittedPhysicalMemory());
  ForAll<ExternalBackingStoreType>(
      [this, page](ExternalBackingStoreType type, int index) {
        DecrementExternalBackingStoreBytes(
            type, page->ExternalBackingStoreBytes(type));
      });
}

void SemiSpace::MovePageToTheEnd(PageMetadata* page) {
  DCHECK_EQ(page->owner(), this);
  memory_chunk_list_.Remove(page);
  memory_chunk_list_.PushBack(page);
  current_page_ = page;
}

void SemiSpace::Swap(SemiSpace* from, SemiSpace* to) {
  // We won't be swapping semispaces without data in them.
  DCHECK(from->first_page());
  DCHECK(to->first_page());
  DCHECK_EQ(from->maximum_capacity_, to->maximum_capacity_);
  DCHECK_EQ(from->minimum_capacity_, to->minimum_capacity_);
  // We swap all properties but id_.
  std::swap(from->target_capacity_, to->target_capacity_);
  std::swap(from->age_mark_, to->age_mark_);
  std::swap(from->memory_chunk_list_, to->memory_chunk_list_);
  std::swap(from->current_page_, to->current_page_);
  ForAll<ExternalBackingStoreType>(
      [from, to](ExternalBackingStoreType type, int index) {
        const size_t tmp = from->external_backing_store_bytes_[index].load(
            std::memory_order_relaxed);
        from->external_backing_store_bytes_[index].store(
            to->external_backing_store_bytes_[index].load(
                std::memory_order_relaxed),
            std::memory_order_relaxed);
        to->external_backing_store_bytes_[index].store(
            tmp, std::memory_order_relaxed);
      });
  std::swap(from->committed_physical_memory_, to->committed_physical_memory_);
  {
    // Swap committed atomic counters.
    size_t to_commited = to->committed_.load();
    to->committed_.store(from->committed_.load());
    from->committed_.store(to_commited);
  }
  std::swap(from->quarantined_pages_count_, to->quarantined_pages_count_);

  // Swapping the `memory_cunk_list_` essentially swaps out the pages (actual
  // payload) from to and from space.
  to->FixPagesFlags();
  from->FixPagesFlags();
}

void SemiSpace::IncrementCommittedPhysicalMemory(size_t increment_value) {
  if (!base::OS::HasLazyCommits()) return;
  DCHECK_LE(committed_physical_memory_,
            committed_physical_memory_ + increment_value);
  committed_physical_memory_ += increment_value;
}

void SemiSpace::DecrementCommittedPhysicalMemory(size_t decrement_value) {
  if (!base::OS::HasLazyCommits()) return;
  DCHECK_LE(decrement_value, committed_physical_memory_);
  committed_physical_memory_ -= decrement_value;
}

void SemiSpace::AddRangeToActiveSystemPages(Address start, Address end) {
  PageMetadata* page = current_page();
  MemoryChunk* chunk = page->Chunk();

  DCHECK_LE(chunk->address(), start);
  DCHECK_LT(start, end);
  DCHECK_LE(end, chunk->address() + PageMetadata::kPageSize);

  const size_t added_pages = page->active_system_pages()->Add(
      chunk->Offset(start), chunk->Offset(end),
      MemoryAllocator::GetCommitPageSizeBits());
  IncrementCommittedPhysicalMemory(added_pages *
                                   MemoryAllocator::GetCommitPageSize());
}

void SemiSpace::set_age_mark(Address mark) {
  age_mark_ = mark;
  PageMetadata* age_mark_page = PageMetadata::FromAllocationAreaAddress(mark);
  size_t below_age_mark_pages = 0;
  DCHECK_EQ(age_mark_page->owner(), this);
  // Mark all pages up to the one containing mark.
  for (PageMetadata* p : *this) {
    below_age_mark_pages++;
    p->Chunk()->SetFlagNonExecutable(MemoryChunk::NEW_SPACE_BELOW_AGE_MARK);
    if (p == age_mark_page) break;
  }
  DCHECK_LT(quarantined_pages_count_, below_age_mark_pages);
  USE(below_age_mark_pages);
}

std::unique_ptr<ObjectIterator> SemiSpace::GetObjectIterator(Heap* heap) {
  // Use the SemiSpaceNewSpace::NewObjectIterator to iterate the ToSpace.
  UNREACHABLE();
}

#ifdef DEBUG
void SemiSpace::Print() {}
#endif

#ifdef VERIFY_HEAP
void SemiSpace::VerifyPageMetadata() const {
  bool is_from_space = (id_ == kFromSpace);
  size_t external_backing_store_bytes[static_cast<int>(
      ExternalBackingStoreType::kNumValues)] = {0};

  size_t actual_pages = 0;
  size_t computed_committed_physical_memory = 0;

  for (const PageMetadata* page : *this) {
    const MemoryChunk* chunk = page->Chunk();
    CHECK_EQ(page->owner(), this);
    CHECK(chunk->InNewSpace());
    CHECK(chunk->IsFlagSet(is_from_space ? MemoryChunk::FROM_PAGE
                                         : MemoryChunk::TO_PAGE));
    CHECK(!chunk->IsFlagSet(is_from_space ? MemoryChunk::TO_PAGE
                                          : MemoryChunk::FROM_PAGE));
    CHECK(chunk->IsFlagSet(MemoryChunk::POINTERS_TO_HERE_ARE_INTERESTING));
    CHECK(!chunk->IsQuarantined());
    if (!is_from_space) {
      // The pointers-from-here-are-interesting flag isn't updated dynamically
      // on from-space pages, so it might be out of sync with the marking state.
      if (page->heap()->incremental_marking()->IsMarking()) {
        CHECK(page->heap()->incremental_marking()->IsMajorMarking());
        CHECK(
            chunk->IsFlagSet(MemoryChunk::POINTERS_FROM_HERE_ARE_INTERESTING));
      } else {
        CHECK(
            !chunk->IsFlagSet(MemoryChunk::POINTERS_FROM_HERE_ARE_INTERESTING));
      }
      CHECK_IMPLIES(actual_pages < quarantined_pages_count_,
                    chunk->IsFlagSet(MemoryChunk::NEW_SPACE_BELOW_AGE_MARK));
    }
    ForAll<ExternalBackingStoreType>(
        [&external_backing_store_bytes, page](ExternalBackingStoreType type,
                                              int index) {
          external_backing_store_bytes[index] +=
              page->ExternalBackingStoreBytes(type);
        });

    computed_committed_physical_memory += page->CommittedPhysicalMemory();

    CHECK_IMPLIES(page->list_node().prev(),
                  page->list_node().prev()->list_node().next() == page);
    actual_pages++;
  }
  CHECK_EQ(actual_pages * PageMetadata::kPageSize, CommittedMemory());
  CHECK_EQ(computed_committed_physical_memory, CommittedPhysicalMemory());
  ForAll<ExternalBackingStoreType>(
      [this, external_backing_store_bytes](ExternalBackingStoreType type,
                                           int index) {
        CHECK_EQ(external_backing_store_bytes[index],
                 ExternalBackingStoreBytes(type));
      });
}
#endif  // VERIFY_HEAP

#ifdef DEBUG
void SemiSpace::AssertValidRange(Address start, Address end) {
  // Addresses belong to same semi-space
  PageMetadata* page = PageMetadata::FromAllocationAreaAddress(start);
  PageMetadata* end_page = PageMetadata::FromAllocationAreaAddress(end);
  SemiSpace* space = reinterpret_cast<SemiSpace*>(page->owner());
  DCHECK_EQ(space, end_page->owner());
  // Start address is before end address, either on same page,
  // or end address is on a later page in the linked list of
  // semi-space pages.
  if (page == end_page) {
    DCHECK_LE(start, end);
  } else {
    while (page != end_page) {
      page = page->next_page();
    }
    DCHECK(page);
  }
}
#endif

void SemiSpace::MoveQuarantinedPage(MemoryChunk* chunk) {
  // Quarantining pages happens at the end of scavenge, after the semi spaces
  // have been swapped. Thus, the quarantined page originates from "from space"
  // to is moved to "to space" to keep pinned objects as live.
  DCHECK_EQ(kToSpace, id_);
  DCHECK(chunk->IsQuarantined());
  DCHECK(chunk->IsFromPage());
  PageMetadata* page = PageMetadata::cast(chunk->Metadata());
  SemiSpace& from_space = heap_->semi_space_new_space()->from_space();
  DCHECK_EQ(&from_space, page->owner());
  DCHECK_NE(&from_space, this);
  from_space.RemovePage(page);
  chunk->ClearFlagNonExecutable(MemoryChunk::IS_QUARANTINED);
  chunk->ClearFlagNonExecutable(MemoryChunk::FROM_PAGE);
  chunk->SetFlagNonExecutable(MemoryChunk::TO_PAGE);
  page->set_owner(this);
  AccountCommitted(PageMetadata::kPageSize);
  IncrementCommittedPhysicalMemory(page->CommittedPhysicalMemory());
  DCHECK(!memory_chunk_list_.Empty());
  memory_chunk_list_.PushFront(page);
  quarantined_pages_count_++;
}

// -----------------------------------------------------------------------------
// NewSpace implementation

NewSpace::NewSpace(Heap* heap)
    : SpaceWithLinearArea(heap, NEW_SPACE, nullptr) {}

void NewSpace::PromotePageToOldSpace(PageMetadata* page) {
  DCHECK(!page->Chunk()->IsFlagSet(MemoryChunk::PAGE_NEW_OLD_PROMOTION));
  DCHECK(page->Chunk()->InYoungGeneration());
  RemovePage(page);
  PageMetadata* new_page = PageMetadata::ConvertNewToOld(page);
  DCHECK(!new_page->Chunk()->InYoungGeneration());
  USE(new_page);
}

// -----------------------------------------------------------------------------
// SemiSpaceNewSpace implementation

SemiSpaceNewSpace::SemiSpaceNewSpace(Heap* heap,
                                     size_t initial_semispace_capacity,
                                     size_t max_semispace_capacity)
    : NewSpace(heap),
      to_space_(heap, kToSpace, initial_semispace_capacity,
                max_semispace_capacity),
      from_space_(heap, kFromSpace, initial_semispace_capacity,
                  max_semispace_capacity) {
  DCHECK(initial_semispace_capacity <= max_semispace_capacity);
  if (!to_space_.Commit()) {
    DCHECK(!to_space_.IsCommitted());
    V8::FatalProcessOutOfMemory(heap->isolate(), "New space setup");
  }
  DCHECK(!from_space_.IsCommitted());  // No need to use memory yet.
  ResetCurrentSpace();
}

void SemiSpaceNewSpace::Grow(size_t new_capacity) {
  heap()->safepoint()->AssertActive();
  DCHECK_LT(TotalCapacity(), MaximumCapacity());
  DCHECK_LE(new_capacity, MaximumCapacity());
  if (to_space_.GrowTo(new_capacity)) {
    // Only grow from space if we managed to grow to-space.
    if (!from_space_.GrowTo(new_capacity)) {
      // If we managed to grow to-space but couldn't grow from-space,
      // attempt to shrink to-space.
      to_space_.ShrinkTo(from_space_.target_capacity());
    }
  }
  DCHECK_SEMISPACE_ALLOCATION_TOP(allocation_top(), to_space_);
}

void SemiSpaceNewSpace::set_age_mark_to_top() {
  to_space_.set_age_mark(allocation_top());
}

void SemiSpaceNewSpace::Shrink(size_t new_capacity) {
  if (new_capacity < TotalCapacity()) {
    to_space_.ShrinkTo(new_capacity);
    // Only shrink from-space if we managed to shrink to-space.
    if (from_space_.IsCommitted()) from_space_.Reset();
    from_space_.ShrinkTo(new_capacity);
  }
  DCHECK_SEMISPACE_ALLOCATION_TOP(allocation_top(), to_space_);
  if (!from_space_.IsCommitted()) return;
  from_space_.Uncommit();
}

size_t SemiSpaceNewSpace::CommittedPhysicalMemory() const {
  if (!base::OS::HasLazyCommits()) return CommittedMemory();
  size_t size = to_space_.CommittedPhysicalMemory();
  if (from_space_.IsCommitted()) {
    size += from_space_.CommittedPhysicalMemory();
  }
  return size;
}

bool SemiSpaceNewSpace::EnsureCurrentCapacity() {
  // Order here is important to make use of the page pool.
  return to_space_.EnsureCurrentCapacity() &&
         from_space_.EnsureCurrentCapacity();
}

void SemiSpaceNewSpace::ResetCurrentSpace() {
  to_space_.Reset();
  quarantined_size_ = 0;
  // Clear all mark-bits in the to-space.
  for (PageMetadata* p : to_space_) {
    if (!v8_flags.separate_gc_phases) {
      p->ClearLiveness();
    } else {
      DCHECK(p->IsLivenessClear());
    }
    // Concurrent marking may have local live bytes for this page.
    heap()->concurrent_marking()->ClearMemoryChunkData(p);
  }
  ResetAllocationTopToCurrentPageStart();
}

bool SemiSpaceNewSpace::AddFreshPage() {
  DCHECK_EQ(allocation_top(), to_space_.page_high());

  if (to_space_.AdvancePage()) {
    ResetAllocationTopToCurrentPageStart();
    return true;
  }
  return false;
}
std::optional<std::pair<Address, Address>>
SemiSpaceNewSpace::AllocateOnNewPageBeyondCapacity(
    int size_in_bytes, AllocationAlignment alignment) {
  DCHECK_LT(Available(), size_in_bytes);
  DCHECK(!AddFreshPage());
  DCHECK(heap_->ShouldExpandYoungGenerationOnSlowAllocation(
      PageMetadata::kPageSize));
  to_space_.allow_to_grow_beyond_capacity_ = true;
  if (!to_space_.AllocateFreshPage()) return std::nullopt;
  return Allocate(size_in_bytes, alignment);
}

bool SemiSpaceNewSpace::AddParkedAllocationBuffer(
    int size_in_bytes, AllocationAlignment alignment) {
  int parked_size = 0;
  Address start = 0;
  for (auto it = parked_allocation_buffers_.begin();
       it != parked_allocation_buffers_.end();) {
    parked_size = it->first;
    start = it->second;
    int filler_size = Heap::GetFillToAlign(start, alignment);
    if (size_in_bytes + filler_size <= parked_size) {
      parked_allocation_buffers_.erase(it);
      PageMetadata* page = PageMetadata::FromAddress(start);
      // We move a page with a parked allocation to the end of the pages list
      // to maintain the invariant that the last page is the used one.
      to_space_.MovePageToTheEnd(page);
      SetAllocationTop(start);
      return true;
    } else {
      it++;
    }
  }
  return false;
}

void SemiSpaceNewSpace::ResetParkedAllocationBuffers() {
  parked_allocation_buffers_.clear();
}

int SemiSpaceNewSpace::GetSpaceRemainingOnCurrentPageForTesting() {
  return static_cast<int>(to_space_.page_high() - allocation_top());
}

void SemiSpaceNewSpace::FillCurrentPageForTesting() {
  int remaining = GetSpaceRemainingOnCurrentPageForTesting();
  heap()->CreateFillerObjectAt(allocation_top(), remaining);
  IncrementAllocationTop(to_space_.page_high());
}

#ifdef VERIFY_HEAP
// We do not use the SemiSpaceObjectIterator because verification doesn't assume
// that it works (it depends on the invariants we are checking).
void SemiSpaceNewSpace::Verify(Isolate* isolate,
                               SpaceVerificationVisitor* visitor) const {
  VerifyObjects(isolate, visitor);

  // Check semi-spaces.
  CHECK_EQ(from_space_.id(), kFromSpace);
  CHECK_EQ(to_space_.id(), kToSpace);
  from_space_.VerifyPageMetadata();
  to_space_.VerifyPageMetadata();
}

// We do not use the SemiSpaceObjectIterator because verification doesn't assume
// that it works (it depends on the invariants we are checking).
void SemiSpaceNewSpace::VerifyObjects(Isolate* isolate,
                                      SpaceVerificationVisitor* visitor) const {
  size_t external_space_bytes[static_cast<int>(
      ExternalBackingStoreType::kNumValues)] = {0};
  PtrComprCageBase cage_base(isolate);
  for (const PageMetadata* page = to_space_.first_page(); page;
       page = page->next_page()) {
    visitor->VerifyPage(page);

    Address current_address = page->area_start();

    while (!PageMetadata::IsAlignedToPageSize(current_address)) {
      Tagged<HeapObject> object = HeapObject::FromAddress(current_address);

      // The first word should be a map, and we expect all map pointers to
      // be in map space or read-only space.
      int size = object->Size(cage_base);

      visitor->VerifyObject(object);

      if (IsExternalString(object, cage_base)) {
        Tagged<ExternalString> external_string = Cast<ExternalString>(object);
        size_t string_size = external_string->ExternalPayloadSize();
        external_space_bytes[static_cast<int>(
            ExternalBackingStoreType::kExternalString)] += string_size;
      }

      current_address += ALIGN_TO_ALLOCATION_ALIGNMENT(size);
    }

    visitor->VerifyPageDone(page);
  }

  ForAll<ExternalBackingStoreType>(
      [this, external_space_bytes](ExternalBackingStoreType type, int index) {
        if (type == ExternalBackingStoreType::kArrayBuffer) {
          return;
        }
        CHECK_EQ(external_space_bytes[index], ExternalBackingStoreBytes(type));
      });

  if (!v8_flags.concurrent_array_buffer_sweeping) {
    size_t bytes = heap()->array_buffer_sweeper()->young().BytesSlow();
    CHECK_EQ(bytes,
             ExternalBackingStoreBytes(ExternalBackingStoreType::kArrayBuffer));
  }
}
#endif  // VERIFY_HEAP

void SemiSpaceNewSpace::MakeIterable() {
  MakeAllPagesInFromSpaceIterable();
  MakeUnusedPagesInToSpaceIterable();
}

void SemiSpaceNewSpace::MakeAllPagesInFromSpaceIterable() {
  if (!IsFromSpaceCommitted()) return;

  // Fix all pages in the "from" semispace.
  for (PageMetadata* page : from_space()) {
    heap()->CreateFillerObjectAt(page->area_start(),
                                 static_cast<int>(page->area_size()));
  }
}

void SemiSpaceNewSpace::MakeUnusedPagesInToSpaceIterable() {
  PageIterator it(to_space().current_page());

  // Fix the remaining unused pages in the "to" semispace.
  for (PageMetadata* page = *(++it); page != nullptr; page = *(++it)) {
    heap()->CreateFillerObjectAt(page->area_start(),
                                 static_cast<int>(page->area_size()));
  }
}

bool SemiSpaceNewSpace::IsAddressBelowAgeMarkForSpace(const SemiSpace& space,
                                                      Address address) const {
  PageMetadata* page = PageMetadata::FromAddress(address);
  Address current_age_mark = space.age_mark();
  return page->Chunk()->IsFlagSet(MemoryChunk::NEW_SPACE_BELOW_AGE_MARK) &&
         (!page->ContainsLimit(current_age_mark) || address < current_age_mark);
}

bool SemiSpaceNewSpace::ShouldBePromoted(Address address) const {
  return IsAddressBelowAgeMarkForSpace(from_space_, address);
}

bool SemiSpaceNewSpace::ShouldPageBePromoted(Address address) const {
  MemoryChunk* chunk = MemoryChunk::FromAddress(address);
  Address current_age_mark = from_space_.age_mark();
  if (!chunk->IsFlagSet(MemoryChunk::NEW_SPACE_BELOW_AGE_MARK)) {
    return false;
  }
  // If the page contains the current age mark, it contains both objects in the
  // interemediate generation (that could be promoted to old space) and new
  // objects (that should remain in new space). When pinning an intermediate
  // generation object on this page, we don't yet know whether or not the page
  // will also contain pinned new objects (that will prevent us from promoting
  // the page). Thus, we conservatively keep the page in new space. Pinned
  // objects on it will either die or be promoted in the next GC cycle.
  return !chunk->Metadata()->ContainsLimit(current_age_mark);
}

#if DEBUG
bool SemiSpaceNewSpace::IsAllocationBelowAgeMark(Address address) const {
  return IsAddressBelowAgeMarkForSpace(to_space_, address);
}
#endif  // DEBUG

std::unique_ptr<ObjectIterator> SemiSpaceNewSpace::GetObjectIterator(
    Heap* heap) {
  return std::unique_ptr<ObjectIterator>(new SemiSpaceObjectIterator(this));
}

bool SemiSpaceNewSpace::ContainsSlow(Address a) const {
  return from_space_.ContainsSlow(a) || to_space_.ContainsSlow(a);
}

size_t SemiSpaceNewSpace::Size() const {
  size_t top = allocation_top();

  DCHECK_GE(top, to_space_.page_low());
  return QuarantinedSize() +
         (to_space_.current_capacity() - PageMetadata::kPageSize) /
             PageMetadata::kPageSize *
             MemoryChunkLayout::AllocatableMemoryInDataPage() +
         static_cast<size_t>(top - to_space_.page_low());
}

size_t SemiSpaceNewSpace::AllocatedSinceLastGC() const {
  const Address age_mark = to_space_.age_mark();
  DCHECK_NE(age_mark, kNullAddress);
  DCHECK_NE(allocation_top(), kNullAddress);
  PageMetadata* const age_mark_page =
      PageMetadata::FromAllocationAreaAddress(age_mark);
  PageMetadata* const last_page =
      PageMetadata::FromAllocationAreaAddress(allocation_top());
  PageMetadata* current_page = age_mark_page;
  size_t allocated = 0;
  if (current_page != last_page) {
    DCHECK_EQ(current_page, age_mark_page);
    DCHECK_GE(age_mark_page->area_end(), age_mark);
    allocated += age_mark_page->area_end() - age_mark;
    current_page = current_page->next_page();
  } else {
    DCHECK_GE(allocation_top(), age_mark);
    return allocation_top() - age_mark;
  }
  while (current_page != last_page) {
    DCHECK_NE(current_page, age_mark_page);
    allocated += MemoryChunkLayout::AllocatableMemoryInDataPage();
    current_page = current_page->next_page();
  }
  DCHECK_GE(allocation_top(), current_page->area_start());
  allocated += allocation_top() - current_page->area_start();
  DCHECK_LE(allocated, Size());
  return allocated;
}

void SemiSpaceNewSpace::GarbageCollectionPrologue() {
  ResetParkedAllocationBuffers();

  // We need to commit from space here to be able to check for from/to space
  // pages later on in the GC. We need to commit before sweeping starts to avoid
  // empty pages being reused for commiting from space and thus ending up with
  // remembered set entries that point to from space instead of freed memory.
  if (!from_space_.Commit()) {
    heap_->FatalProcessOutOfMemory("Committing semi space failed.");
  }
}

void SemiSpaceNewSpace::EvacuatePrologue() {
  // Flip the semispaces. After flipping, to space is empty and from space has
  // live objects.
  SemiSpace::Swap(&from_space_, &to_space_);
  ResetCurrentSpace();
  DCHECK_EQ(0u, Size());
}

void SemiSpaceNewSpace::GarbageCollectionEpilogue() {
  DCHECK(!heap()->allocator()->new_space_allocator()->IsLabValid());
  set_age_mark_to_top();

  if (heap::ShouldZapGarbage() || v8_flags.clear_free_memory) {
    ZapUnusedMemory();
  }

  MakeAllPagesInFromSpaceIterable();
}

void SemiSpaceNewSpace::ZapUnusedMemory() {
  if (!IsFromSpaceCommitted()) {
    return;
  }
  for (PageMetadata* page : PageRange(from_space().first_page(), nullptr)) {
    heap::ZapBlock(page->area_start(),
                   page->HighWaterMark() - page->area_start(),
                   heap::ZapValue());
  }
}

void SemiSpaceNewSpace::RemovePage(PageMetadata* page) {
  DCHECK(!page->Chunk()->IsToPage());
  DCHECK(page->Chunk()->IsFromPage());
  from_space().RemovePage(page);
}

bool SemiSpaceNewSpace::IsPromotionCandidate(
    const MutablePageMetadata* page) const {
  return !page->Contains(age_mark());
}

std::optional<std::pair<Address, Address>> SemiSpaceNewSpace::Allocate(
    int size_in_bytes, AllocationAlignment alignment) {
  size_in_bytes = ALIGN_TO_ALLOCATION_ALIGNMENT(size_in_bytes);
  DCHECK_SEMISPACE_ALLOCATION_TOP(allocation_top(), to_space_);

  Address top = allocation_top();
  Address high = to_space_.page_high();
  int filler_size = Heap::GetFillToAlign(top, alignment);
  int aligned_size_in_bytes = size_in_bytes + filler_size;

  if (top + aligned_size_in_bytes <= high) {
    IncrementAllocationTop(high);
    return std::pair(top, high);
  }

  int remaining_in_page = static_cast<int>(high - top);
  heap()->CreateFillerObjectAt(top, remaining_in_page);
  SetAllocationTop(high);

  // We park unused allocation buffer space of allocations happening from the
  // mutator.
  if (v8_flags.allocation_buffer_parking &&
      heap()->gc_state() == Heap::NOT_IN_GC &&
      remaining_in_page >= kAllocationBufferParkingThreshold) {
    parked_allocation_buffers_.push_back(
        ParkedAllocationBuffer(remaining_in_page, top));
  }

  if (AddFreshPage()) {
    Address start = allocation_top();
    Address end = to_space_.page_high();
    DCHECK_EQ(0, Heap::GetFillToAlign(start, alignment));
    IncrementAllocationTop(end);
    return std::pair(start, end);
  }

  if (v8_flags.allocation_buffer_parking &&
      AddParkedAllocationBuffer(size_in_bytes, alignment)) {
    Address start = allocation_top();
    Address end = to_space_.page_high();
    DCHECK_LT(start, end);
    IncrementAllocationTop(end);
    return std::pair(start, end);
  }

  return std::nullopt;
}

void SemiSpaceNewSpace::Free(Address start, Address end) {
  DCHECK_LE(start, end);
  heap()->CreateFillerObjectAt(start, static_cast<int>(end - start));

  if (end == allocation_top()) {
    DecrementAllocationTop(start);
  }
}

AllocatorPolicy* SemiSpaceNewSpace::CreateAllocatorPolicy(
    MainAllocator* allocator) {
  return new SemiSpaceNewSpaceAllocatorPolicy(this, allocator);
}

void SemiSpaceNewSpace::MoveQuarantinedPage(MemoryChunk* chunk) {
  to_space_.MoveQuarantinedPage(chunk);
}

// -----------------------------------------------------------------------------
// PagedSpaceForNewSpace implementation

PagedSpaceForNewSpace::PagedSpaceForNewSpace(Heap* heap,
                                             size_t initial_capacity,
                                             size_t max_capacity)
    : PagedSpaceBase(heap, NEW_SPACE, NOT_EXECUTABLE,
                     FreeList::CreateFreeListForNewSpace(),
                     CompactionSpaceKind::kNone),
      initial_capacity_(RoundDown(initial_capacity, PageMetadata::kPageSize)),
      max_capacity_(RoundDown(max_capacity, PageMetadata::kPageSize)),
      target_capacity_(initial_capacity_) {
  DCHECK_LE(initial_capacity_, max_capacity_);
}

PageMetadata* PagedSpaceForNewSpace::InitializePage(
    MutablePageMetadata* mutable_page_metadata) {
  DCHECK_EQ(identity(), NEW_SPACE);
  MemoryChunk* chunk = mutable_page_metadata->Chunk();
  PageMetadata* page = PageMetadata::cast(mutable_page_metadata);
  DCHECK_EQ(
      MemoryChunkLayout::AllocatableMemoryInMemoryChunk(page->owner_identity()),
      page->area_size());
  // Make sure that categories are initialized before freeing the area.
  page->ResetAllocationStatistics();
  chunk->SetFlagNonExecutable(MemoryChunk::TO_PAGE);
  page->ClearLiveness();
  page->AllocateFreeListCategories();
  page->InitializeFreeListCategories();
  page->list_node().Initialize();
  chunk->InitializationMemoryFence();
  return page;
}

void PagedSpaceForNewSpace::Grow(size_t new_capacity) {
  heap()->safepoint()->AssertActive();
  DCHECK_LT(TotalCapacity(), MaximumCapacity());
  DCHECK_LE(new_capacity, MaximumCapacity());
  target_capacity_ = new_capacity;
}

bool PagedSpaceForNewSpace::StartShrinking() {
  DCHECK(heap()->tracer()->IsInAtomicPause());
  size_t new_target_capacity =
      RoundUp(std::max(initial_capacity_, 2 * Size()), PageMetadata::kPageSize);
  if (new_target_capacity > target_capacity_) return false;
  target_capacity_ = new_target_capacity;
  return true;
}

void PagedSpaceForNewSpace::FinishShrinking() {
  DCHECK(heap()->tracer()->IsInAtomicPause());
  if (current_capacity_ > target_capacity_) {
#if DEBUG
    // If `current_capacity_` is higher than `target_capacity_`, i.e. the
    // space could not be shrunk all the way down to `target_capacity_`, it
    // must mean that all pages contain live objects.
    for (PageMetadata* page : *this) {
      DCHECK_NE(0, page->live_bytes());
    }
#endif  // DEBUG
    target_capacity_ = current_capacity_;
  }
}

size_t PagedSpaceForNewSpace::AddPage(PageMetadata* page) {
  current_capacity_ += PageMetadata::kPageSize;
  return PagedSpaceBase::AddPage(page);
}

void PagedSpaceForNewSpace::RemovePage(PageMetadata* page) {
  DCHECK_LE(PageMetadata::kPageSize, current_capacity_);
  current_capacity_ -= PageMetadata::kPageSize;
  PagedSpaceBase::RemovePage(page);
}

void PagedSpaceForNewSpace::ReleasePage(PageMetadata* page) {
  DCHECK_LE(PageMetadata::kPageSize, current_capacity_);
  current_capacity_ -= PageMetadata::kPageSize;
  PagedSpaceBase::ReleasePageImpl(page, MemoryAllocator::FreeMode::kPool);
}

bool PagedSpaceForNewSpace::ShouldReleaseEmptyPage() const {
  return current_capacity_ > target_capacity_;
}

void PagedSpaceForNewSpace::AllocatePageUpToCapacityForTesting() {
  while (current_capacity_ < target_capacity_) {
    if (!AllocatePage()) return;
  }
}

bool PagedSpaceForNewSpace::AllocatePage() {
  // Verify that the free space map is already initialized. Otherwise, new free
  // list entries will be invalid.
  DCHECK_NE(kNullAddress,
            heap()->isolate()->root(RootIndex::kFreeSpaceMap).ptr());
  return TryExpand(heap()->main_thread_local_heap(),
                   AllocationOrigin::kRuntime);
}

bool PagedSpaceForNewSpace::IsPromotionCandidate(
    const MutablePageMetadata* page) const {
  DCHECK_EQ(this, page->owner());
  if (page == last_lab_page_) return false;
  return page->AllocatedLabSize() <=
         static_cast<size_t>(
             PageMetadata::kPageSize *
             v8_flags.minor_ms_page_promotion_max_lab_threshold / 100);
}

size_t PagedSpaceForNewSpace::AllocatedSinceLastGC() const {
  return Size() - size_at_last_gc_;
}

size_t PagedSpaceForNewSpace::Available() const {
  return PagedSpaceBase::Available();
}

#ifdef VERIFY_HEAP
void PagedSpaceForNewSpace::Verify(Isolate* isolate,
                                   SpaceVerificationVisitor* visitor) const {
  PagedSpaceBase::Verify(isolate, visitor);

  CHECK_EQ(current_capacity_, PageMetadata::kPageSize * CountTotalPages());

  auto sum_allocated_labs = [](size_t sum, const PageMetadata* page) {
    return sum + page->AllocatedLabSize();
  };
  CHECK_EQ(AllocatedSinceLastGC(),
           std::accumulate(begin(), end(), 0, sum_allocated_labs));
}
#endif  // VERIFY_HEAP

// -----------------------------------------------------------------------------
// PagedNewSpace implementation

PagedNewSpace::PagedNewSpace(Heap* heap, size_t initial_capacity,
                             size_t max_capacity)
    : NewSpace(heap), paged_space_(heap, initial_capacity, max_capacity) {}

PagedNewSpace::~PagedNewSpace() {
  paged_space_.TearDown();
}

AllocatorPolicy* PagedNewSpace::CreateAllocatorPolicy(
    MainAllocator* allocator) {
  return new PagedNewSpaceAllocatorPolicy(this, allocator);
}

}  // namespace internal
}  // namespace v8
