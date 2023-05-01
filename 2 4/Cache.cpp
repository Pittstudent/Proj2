#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <iostream>

#include "Cache.h"
#include "CPU.h"


Cache::Cache(const char *name)
: MemObj(name)
  ,readHits("readHits")
  ,readMisses("readMisses")
  ,writeHits("writeHits")
  ,writeMisses("writeMisses")
  ,writeBacks("writeBacks")
{
  GError *error = NULL;
  // Get hit delay from config file
  hitDelay = g_key_file_get_integer(config->keyfile, name, "hitDelay", NULL);
  if(error != NULL) g_error (error->message);
  // Create cacheCore after parsing config file
  int size = g_key_file_get_integer(config->keyfile, name, "size", &error);
  if(error != NULL) g_error (error->message);
  int assoc = g_key_file_get_integer(config->keyfile, name, "assoc", NULL);
  if(error != NULL) g_error (error->message);
  int bsize = g_key_file_get_integer(config->keyfile, name, "bsize", NULL);
  if(error != NULL) g_error (error->message);
  gchar* pStr = g_key_file_get_string(config->keyfile, name, "replPolicy", NULL);
  if(error != NULL) g_error (error->message);

  assert(size > 0);
  assert(assoc > 0);
  assert(bsize > 0);
  assert(pStr != NULL);

  cacheCore = new CacheCore(size, assoc, bsize, pStr);

  g_free(pStr);
}

Cache::~Cache()
{
  delete cacheCore;
}

void Cache::access(MemRequest *mreq)
{
  mreq->addLatency(hitDelay);

  if(verbose) {
    const char *memOp;
    switch(mreq->getMemOperation()){
      case MemRead: memOp = "MemRead"; break;
      case MemWrite: memOp = "MemWrite"; break;
      case MemWriteBack: memOp = "MemWriteBack"; break;
      default: assert(0); break;
    }
    printf("%s->access(%s, addr: %u, latency: %u)\n", getName().c_str(), memOp, mreq->getAddr(), mreq->getLatency());
  }

  switch(mreq->getMemOperation()){
    case MemRead:
      read(mreq);
      break;
    case MemWrite:
      write(mreq);
      break;
    case MemWriteBack:
      writeBack(mreq);
      break;
    default:
      assert(0);
      break;
  }
}

// Get string that describes MemObj
std::string Cache::toString() const
{
  std::string ret;
  ret += "[" + getName() + "]\n";
  ret += "device type = cache\n";
  ret += "write policy = " + getWritePolicy() + "\n";
  ret += "hit time = " + std::to_string(hitDelay) + "\n";
  ret += cacheCore->toString();
  ret += "lower level = " + getLowerLevel() + "\n";
  return ret;
}

// Get string that summarizes access statistics
std::string Cache::getStatString() const
{
  std::string ret;
  ret += getName() + ":";
  ret += readHits.toString() + ":";
  ret += readMisses.toString() + ":";
  ret += writeHits.toString() + ":";
  ret += writeMisses.toString() + ":";
  ret += writeBacks.toString();
  return ret;
}

// Get string that dumps all valid lines in cache
std::string Cache::getContentString() const
{
  std::string ret;
  ret += "[" + getName() + "]\n";
  ret += cacheCore->getContentString();
  return ret;
}

// WBCache: Write back cache.  Allocates a dirty block on write miss.

WBCache::WBCache(const char *name)
: Cache(name)
{
  // nothing to do
}
WBCache::~WBCache() 
{
  // nothing to do
}

void WBCache::read(MemRequest *mreq) {
    // Check if the requested block is already present in the cache
    if (lookup(mreq->getAddr())) {
        // The block is present in the cache, so we can fulfill the request
        readHits.inc();
        // Update the LRU list to reflect that this block was recently accessed
        updateLRU(mreq->getAddr());
        // Forward the read request to the higher-level cache or the processor
        forwardRequest(mreq);
    } else {
        // The block is not present in the cache, so we need to request it from
        // the lower-level memory
        readMisses.inc();
        // Forward the read request to the lower-level memory
        getLowerLevelMemObj()->access(mreq);
    }
}

void WBCache::write(MemRequest *mreq) {
    // Check if the requested block is already present in the cache
    if (lookup(mreq->getAddr())) {
        // The block is present in the cache, so we can fulfill the request
        writeHits.inc();
        // Update the LRU list to reflect that this block was recently accessed
        updateLRU(mreq->getAddr());
        // Mark the block as dirty
        markDirty(mreq->getAddr());
        // Forward the write request to the higher-level cache or the processor
        forwardRequest(mreq);
    } else {
        // The block is not present in the cache, so we need to request it from
        // the lower-level memory
        writeMisses.inc();
        // Forward the write request to the lower-level memory
        getLowerLevelMemObj()->access(mreq);
    }
}


void WBCache::writeBack(MemRequest *mreq) {
  writeBacks.increment();
  MemRequest *downreq = new MemRequest(mreq->getAddr(), MemWriteBack);
  access(downreq);
  delete downreq;
 

// WTCache: Write through cache. Always propagates writes down.

WTCache::WTCache(const char *name)
: Cache(name)
{
  // nothing to do 
}

WTCache::~WTCache()
{
  // nothing to do
}

void WTCache::read(MemRequest *mreq)
{
  uint64_t blockAddr = getBlockAddr(mreq->addr);

  if (cacheLookup(blockAddr)) {
    // Cache hit
    readHits.inc();
    updateLRU(blockAddr);
    mreq->done(this, MemRequestStatus::MEM_REQ_DONE);
  } else {
    // Cache miss
    readMisses.inc();
    MemRequest *lowerReq = new MemRequest(getLowerLevelMemObj(), mreq->addr, mreq->size, mreq->flags);
    lowerReq->setCallback(this, (MemReqCallback)&WTCache::readDone);
    lowerReq->setDependency(mreq);
    lowerReq->send();
  }
}

void WTCache::write(MemRequest *mreq)
{
  uint64_t blockAddr = getBlockAddr(mreq->addr);

  if (cacheLookup(blockAddr)) {
    // Cache hit
    writeHits.inc();
    updateLRU(blockAddr);
    mreq->done(this, MemRequestStatus::MEM_REQ_DONE);
    // Mark the block as dirty
    cache[blockAddr].dirty = true;
  } else {
    // Cache miss
    writeMisses.inc();
    MemRequest *lowerReq = new MemRequest(getLowerLevelMemObj(), mreq->addr, mreq->size, mreq->flags);
    lowerReq->setCallback(this, (MemReqCallback)&WTCache::writeDone);
    lowerReq->setDependency(mreq);
    lowerReq->send();
  }
}

void WTCache::readDone(MemRequest *mreq)
{
  uint64_t blockAddr = getBlockAddr(mreq->addr);

  // Copy the data from lower level memory into cache
  memcpy(cache[blockAddr].data, mreq->data, blockSize);
  // Mark the block as not dirty
  cache[blockAddr].dirty = false;
  // Update LRU
  updateLRU(blockAddr);
  // Complete the request
  mreq->done(this, MemRequestStatus::MEM_REQ_DONE);
}

void WTCache::writeDone(MemRequest *mreq)
{
  uint64_t blockAddr = getBlockAddr(mreq->addr);

  // Copy the data from the request into cache
  memcpy(cache[blockAddr].data, mreq->data, blockSize);
  // Mark the block as not dirty
  cache[blockAddr].dirty = false;
  // Mark the block as valid
  cache[blockAddr].valid = true;
  // Update LRU
//  updateLRU(blockAddr);
  // Complete the request
  mreq->done(this, MemRequestStatus::MEM_REQ_DONE);
}

void WTCache::writeBack(MemRequest *mreq)
{
  // No reasonable design will have a WB cache on top of a WT cache
  assert(0);
}
