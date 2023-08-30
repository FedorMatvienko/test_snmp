#pragma once
#include <iostream>
#include <fstream>
#include <vector>
#include <thread> 
#include <chrono>
#include <mutex>
#include <filesystem>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <jsoncpp/json/json.h>
using namespace std;

mutex mutQueue;

class DevicesSnmp
{
public:

    //Параметры устройств
    string url;
    uint64_t version;
    string community;
    uint64_t timeout;
    vector<string> oids;
    

    DevicesSnmp( vector<string> oids_in,
                 const string url_in,
                 uint64_t version_in=1,
                 const string community_in="public",
                 uint64_t timeout_in=5000): oids( oids_in ),
                                            url( url_in ),
                                            version( version_in ),
                                            community( community_in ),
                                            timeout( timeout_in ){}
};
namespace snmp
{
    void session_snmp( DevicesSnmp );
}