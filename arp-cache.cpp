/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {
	
	
/*
!! The ARP cache entries hold IP->MAC mappings and are timed out every SR_ARPCACHE_TO seconds. !!

If ARP? -> Handle ARP!
  I. ARP request? à Send ARP reply
  II. ARP reply?
    - Store IP/MAC info (insertArpEntry() function)
      then send cached packets out! 
/////

Opcode: 1 - ARP request
        2 - ARP reply 
*/

static bool removed = false;

void
ArpCache::handle_arpreq(std::shared_ptr<ArpRequest> req)
{
  struct arp_hdr arp_head;
  struct ethernet_hdr eth_head;

  /*if now - req->timeSent > seconds(1)
           if req->nTimesSent >= 5:
               send icmp host unreachable to source addr of all pkts waiting
                 on this request
               cache.removeRequest(req)
           else:
               send arp request
               req->timeSent = now
               req->nTimesSent++
  */
  //printf("Handling ARP request\n");
  if((steady_clock::now() - req->timeSent) > seconds(1)){
    if(req->nTimesSent >= 5){
      //send icmp host unreachable to source addr of all pkts waiting on this request ??

      m_arpRequests.remove(req);  
      //removeRequest(req);
      removed = true;
      return;
    }
    else{
      //send the request

      //in core/utils.cpp -> print_hdrs();
      //in simple-router.cpp -> sendPacket();

      Buffer pckt (42,0); //check "requestPacket"
      
      const Interface* sendingIface = m_router.findIfaceByName(m_router.getRoutingTable().lookup(req->ip).ifName);
      
      //Ethernet Frame 
      memset(eth_head.ether_dhost, 255, ETHER_ADDR_LEN);//Broadcast
      memcpy(eth_head.ether_shost, &sendingIface->addr[0], ETHER_ADDR_LEN);
      eth_head.ether_type = htons(0x0806);
      

      arp_head.arp_pln = 4;
      arp_head.arp_hrd = htons(0x0001);
      arp_head.arp_op = htons(0x0001);
      arp_head.arp_pro = htons(0x0800);
      arp_head.arp_hln = 6;
      
      memset(arp_head.arp_tha, 255, ETHER_ADDR_LEN);
      memcpy(arp_head.arp_sha, &sendingIface->addr[0], ETHER_ADDR_LEN);
      memcpy(&arp_head.arp_sip, &sendingIface->ip, sizeof(arp_head.arp_sip));
      memcpy(&arp_head.arp_tip, &req->ip, sizeof(arp_head.arp_tip));
      
      
      memcpy(&pckt[0], &eth_head, sizeof(eth_head));
      memcpy(&pckt[14], &arp_head, sizeof(arp_head));
      m_router.sendPacket(pckt, sendingIface->name);

      //printf("The following Arp reqeust was sent\n");
	  std::cerr << "The following Arp reqeust was sent"  << std::endl; 
      std::cerr << "Interface:" << sendingIface->name << std::endl; 
      print_hdrs(pckt);


      req->timeSent = steady_clock::now();
      req->nTimesSent++;
    }

  }
}
	
	

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{

  // FILL THIS IN
  std::vector<std::shared_ptr<ArpEntry>> toRemove;
  for(const auto& r: m_arpRequests){
    handle_arpreq(r);
    if(removed == true)
      break;
  }

  for(const auto& c: m_cacheEntries){
    if((c->isValid) == 0){
      toRemove.push_back(c);
    }
  }

  for(const auto& e: toRemove){
    m_cacheEntries.remove(e);
  }

}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
