#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>

#include "cache.h"
#include "print_helpers.h"

cache_t *make_cache(int capacity, int block_size, int assoc, enum protocol_t protocol, bool lru_on_invalidate_f)
{
  cache_t *cache = malloc(sizeof(cache_t));
  cache->stats = make_cache_stats();

  cache->capacity = capacity;     // in Bytes
  cache->block_size = block_size; // in Bytes
  cache->assoc = assoc;           // 1, 2, 3... etc.

  // FIX THIS CODE!
  // first, correctly set these 5 variables. THEY ARE ALL WRONG
  // note: you may find math.h's log2 function useful
  cache->n_cache_line = capacity / block_size;
  cache->n_set = capacity / (block_size * assoc);
  cache->n_offset_bit = (int)log2(block_size);
  cache->n_index_bit = (int)log2(capacity / (block_size * assoc));
  cache->n_tag_bit = ADDRESS_SIZE - cache->n_offset_bit - cache->n_index_bit;

  // next create the cache lines and the array of LRU bits
  // - malloc an array with n_rows
  // - for each element in the array, malloc another array with n_col
  // FIX THIS CODE!

  cache->lines = malloc(cache->n_set * sizeof(cache_line_t));
  for (int i = 0; i < cache->n_set; i++)
  {
    cache->lines[i] = malloc(cache->assoc * sizeof(cache_line_t));
  }

  cache->lru_way = malloc(cache->n_set * sizeof(int));

  // initializes cache tags to 0, dirty bits to false,
  // state to INVALID, and LRU bits to 0
  // FIX THIS CODE!
  for (int i = 0; i < cache->n_set; i++)
  {
    for (int j = 0; j < cache->assoc; j++)
    {
      cache->lines[i][j].tag = 0;
      cache->lines[i][j].dirty_f = false;
      cache->lines[i][j].state = INVALID;
    }
  }

  cache->protocol = protocol;
  cache->lru_on_invalidate_f = lru_on_invalidate_f;

  return cache;
}

/* Given a configured cache, returns the tag portion of the given address.
 *
 * Example: a cache with 4 bits each in tag, index, offset
 * in binary -- get_cache_tag(0b111101010001) returns 0b1111
 * in decimal -- get_cache_tag(3921) returns 15
 */
unsigned long get_cache_tag(cache_t *cache, unsigned long addr)
{
  // FIX THIS CODE!
  return addr >> (cache->n_index_bit + cache->n_offset_bit);
}

/* Given a configured cache, returns the index portion of the given address.
 *
 * Example: a cache with 4 bits each in tag, index, offset
 * in binary -- get_cache_index(0b111101010001) returns 0b0101
 * in decimal -- get_cache_index(3921) returns 5
 */
unsigned long get_cache_index(cache_t *cache, unsigned long addr)
{
  // FIX THIS CODE!
  // Contains the address without the offset
  int addrNoOffset = addr >> cache->n_offset_bit;
  int mask = (1 << cache->n_index_bit) - 1;
  return mask & addrNoOffset;
}

/* Given a configured cache, returns the given address with the offset bits zeroed out.
 *
 * Example: a cache with 4 bits each in tag, index, offset
 * in binary -- get_cache_block_addr(0b111101010001) returns 0b111101010000
 * in decimal -- get_cache_block_addr(3921) returns 3920
 */
unsigned long get_cache_block_addr(cache_t *cache, unsigned long addr)
{
  // FIX THIS CODE!
  unsigned long ones = ~0;
  ones = ones << cache->n_offset_bit;
  return ones & addr;
}

// function to implement for task 9
bool vi_ldmiss_stmiss(cache_t *cache, enum action_t action, unsigned long index,
                      unsigned long tag, cache_line_t *line, bool hit, int way)
{

    // direct mapped - don't use way here.
    int way_number = 0;
    bool wb = false;
    if (hit) {
      // hit sequence
      if (line->state == VALID) {
        if (line->dirty_f) {
          line->dirty_f = false;
          wb = true;
        }
        line->state = INVALID;
      }
      else {
        // INVALID
        line->state = INVALID;
      }
    }
    else {
      // miss sequence - do nothing

    }
    update_stats(cache->stats, hit, wb, false, action);
    return hit;
  }


// function to implement for task 10
bool cache_msi(cache_t *cache, unsigned long addr, enum action_t action)
{
  return false;
}

bool basic_load_store(cache_t *cache, enum action_t action, unsigned long index,
                      unsigned long tag, cache_line_t *line, bool hit, int way)
{
  bool wb = false;
  if (hit)
  {
    if (action == STORE)
    {
      line->dirty_f = true;
    }
    cache->lru_way[index] = (way + 1) % cache->assoc;
  }
  else
  {
    line->tag = tag
    if (line->dirty_f)
    {
      wb = true;
      line->dirty_f = false;
    }

    if (action == STORE)
    {
      line->dirty_f = true;
    }
    cache->lru_way[index] = (cache->lru_way[index] + 1) % cache->assoc;
  }
  update_stats(cache->stats, hit, wb, false, action);
  return hit;
}

/* this method takes a cache, an address, and an action
 * it proceses the cache access. functionality in no particular order:
 *   - look up the address in the cache, determine if hit or miss
 *   - update the LRU_way, cacheTags, state, dirty flags if necessary
 *   - update the cache statistics (call update_stats)
 * return true if there was a hit, false if there was a miss
 * Use the "get" helper functions above. They make your life easier.
 */
bool access_cache(cache_t *cache, unsigned long addr, enum action_t action)
{
  // FIX THIS CODE!

  // get tag, index, and block address
  unsigned long index = get_cache_index(cache, addr);
  log_set(index);
  unsigned long tag = get_cache_tag(cache, addr);
  bool hit = false;

  // UNCOMMENT BELOW AFTER TASK 10
  // if (cache->protocol == MSI)
  // {
  //   return cache_msi(cache, addr, action);
  // }

  cache_line_t *set = cache->lines[index];
  cache_line_t *line;
  int way_number = 0;
  // check if you can get a hit
  for (int i = 0; i < cache->assoc; i++)
  {
    cache_line_t *way = &set[i];
    if (cache->protocol == NONE)
    {
      if (tag == way->tag)
      {
        hit = true;
        line = way;
        way_number = i;
        break;
      }
    }

    // UNCOMMENT BELOW AFTER TASK 9
    // else if (cache->protocol == VI)
    // {
    //   if (tag == way->tag && way->state == VALID)
    //   {
    //     hit = true;
    //     line = way;
    //     way_number = i;
    //     break;
    //   }
    // }
  }

  if (!hit)
  {
    line = &set[cache->lru_way[index]];
  }
  if (cache->protocol == NONE)
  {
    if (action == LOAD || action == STORE)
    {
      basic_load_store(cache, action, index, tag, line, hit, way_number);
    }
  }

  // UNCOMMENT BELOW AFTER TASK 9
  // else if (cache->protocol == VI)
  // {
  //   if (action == LOAD || action == STORE)
  //   {
  //     line->state = VALID;
  //     basic_load_store(cache, action, index, tag, line, hit, way_number);
  //   }
  //   else
  //   {
  //     vi_ldmiss_stmiss(cache, action, index, tag, line, hit, way_number);
  //   }
  // }
  log_way(way_number);
  return hit;
}
