/* 
 *  Copyright (c) 2015, Next Generation Intelligent Networks (nextGIN), RC.
 *  Institute of Space Technology
 *  All rights reserved.
 * 
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */



#include <string>
#include <iostream>
#include <osquery/events.h>
#include <osquery/sql.h>
#include <osquery/sdk.h>
#include <osquery/registry.h>
#include <sstream>
#include <csignal>
#include "BrokerConnectionManager.h"
#include "BrokerQueryManager.h"
#include "BrokerQueryPlugin.h"
#include "utility.h"



// :osquery::REGISTER_EXTERNAL to define BrokerQueryManagerPlugin 
REGISTER_EXTERNAL(BrokerQueryManagerPlugin, "config", "brokerQueryManager")



// main runner
int main(int argc, char* argv[]) {
    
   
  // BrokerConnectionManager class pointer
  BrokerConnectionManager* ptBCM;
  // to store  the return values of BrokerQueryManager functions and
  // use it for comparison purpose
  bool processResponse;
  //connection response
  bool connectionResponse;
  //FileReader Class Object
  FileReader fileReader;
  //SignalHandler object to trace kill signal
  SignalHandler *signalHandler = new SignalHandler;
  
 //osquery::runner start logging, threads, etc. for our extension
  osquery::Initializer runner(argc, argv, OSQUERY_EXTENSION);
  LOG(WARNING) <<"Initialized OSquery." ;
  
 
  
//Reads hostName, broker_topic and broker_port form broker.ini file
int fileResponse = fileReader.read();
// if reading is successful
if(fileResponse == 0)
{
    try
    {
        // try setting up signal handler for kill signal
        signalHandler->setupSignalHandler();
        do
        {
            // then make a broker connection manager object
            ptBCM = new BrokerConnectionManager(fileReader.getHostName(),
                fileReader.getBrokerTopic(),
                std::atoi(fileReader.getBrokerConnectionPort().c_str()));
            
            processResponse = false;
            connectionResponse = false;
            // Try to establish connection with master at IP given in
            // "broker.ini"
            connectionResponse = ptBCM->connectToMaster(fileReader.getMasterIp()
                    ,std::chrono::duration<double>
            (std::atoi(fileReader.getRetryInterval().c_str())), signalHandler);
            // When connection is established then process queries
            if (connectionResponse)
            {
                processResponse = ptBCM->getAndProcessQuery(
                        fileReader.getBrokerTopic());
                // if query processing is successful
                if(processResponse)
                {   
                    /*then Track changes and send response to master until 
                     *connection is alive and no kill signal is received
                     */
                    while(ptBCM->isConnectionAlive() &&
                            !signalHandler->gotExitSignal())
                    {
                        ptBCM->trackResponseChangesAndSendResponseToMaster(
                                signalHandler);
                    }
                    ptBCM->getQueryManagerPointer()->sendWarningtoBro("CTRL+C" 
                        " Signal Received");
                    //close broker connection
                    ptBCM->closeBrokerConnection();
                    // if connection is down then reinitialize all query vectors
                    ptBCM->getQueryManagerPointer()->ReInitializeVectors();
                    //delete  BrokerConnectionManager Object
                    delete ptBCM;
                }
                else
                {
                    //free resources
                    ptBCM->getQueryManagerPointer()->ReInitializeVectors();
                    //close broker connection
                    ptBCM->closeBrokerConnection();
                    //delete  BrokerConnectionManager Object
                    delete ptBCM;
                }
            }
            //run until kill signal is received
        } while(!signalHandler->gotExitSignal());
    }
    // catches exception thrown at kill signal setup time
    catch(SignalException& e)
    {
        LOG(ERROR) << "SignalException: " <<e.what();
    }
    // delete SignalHandler object 
    delete signalHandler;
}
    
     
    
LOG(WARNING) <<"Shutting down extension";
// Finally shutdown.
runner.shutdown();
              
return 0;
}
