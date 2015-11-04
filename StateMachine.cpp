/* 
 *  Copyright (c) 2015, Next Generation Intelligent Networks (nextGIN), RC.
 *  Institute of Space Technology
 *  All rights reserved.
 * 
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 */

#include "StateMachine.h"

StateMachine::StateMachine(SignalHandler* handler)
{
    //set the signal handler
    this->signalHandler = handler;
    //set connectionResponse to false
    this->connectionResponse = false;
    // set fileResponse to false
    this->fileResponse = false;
    // set processResponse to false
    this->processResponse = false;
    // set topicResponse to false;
    this->topicResponse = false;
    //set pointer of BrokerConnectionMnager to NULL
    this->ptBCM = NULL;
   /* //build legal state transition map
    this->buildAllowedStateTransitionMap();*/
}


int StateMachine::initializeStateMachine()
{
    //Reads hostName, broker_topic and broker_port form broker.ini file
     fileResponse = fileReader.read();
     // if reading is not successful
     if (fileResponse != 0)
     {
         return  KILL_SIGNAL;
     }
     // if reading is successful
     // then make a broker connection manager object
    ptBCM = new BrokerConnectionManager(getLocalHostIp(),
        fileReader.getBrokerTopic(),
        std::atoi(fileReader.getBrokerConnectionPort().c_str()));

    connectionResponse = false;
    // Try to establish connection with master at IP given in
    // "broker.ini"
    connectionResponse = ptBCM->connectToMaster(fileReader.getMasterIp()
            ,std::chrono::duration<double>
    (std::atoi(fileReader.getRetryInterval().c_str())), signalHandler);
    //if the connection is not established then there must be CTRL +C
    if(!connectionResponse)
        return  KILL_SIGNAL;
    else
        return SUCCESS; 
}

int StateMachine::processEventsInWaitForTopicState()
{
    topicResponse = 0;
    //when connection is established then listen for group topic
    topicResponse=ptBCM->getAndSetTopic();
    if (topicResponse == 0)
    {
        LOG(WARNING) << "Connection Broken" ;

        //delete  BrokerConnectionManager Object
        delete ptBCM;
        return FAILURE;
    }
    else if(topicResponse == -1)
    {
        return KILL_SIGNAL;
    }
    else
    {
        return SUCCESS;
    }
}

int StateMachine::processEventsInGetAndProcessQueriesState()
{
    processResponse = false;
    // When group topic is received then process queries
    processResponse = ptBCM->getAndProcessQuery();
    // if query processing is unsuccessful
    if(!processResponse)
    {
        //close broker connection
        ptBCM->closeBrokerConnection();
        LOG(WARNING) << "Could not Process Queries";

        //reestablish connection and process queries.
        LOG(WARNING) << "Connection Broken" ;
        // if connection is down then reinitialize all query vectors
        ptBCM->getQueryManagerPointer()->ReInitializeVectors();
        //delete  BrokerConnectionManager Object
        delete ptBCM;
        return FAILURE;
    }

    while(ptBCM->isConnectionAlive() &&
                !signalHandler->gotExitSignal())
    {
        ptBCM->trackResponseChangesAndSendResponseToMaster(
                signalHandler);
    }
    //if connection is broken
    if(!ptBCM->isConnectionAlive())
    {
        LOG(WARNING) << "Connection Broken" ;
        // if connection is down then reinitialize all query vectors
        ptBCM->getQueryManagerPointer()->ReInitializeVectors();
        //delete  BrokerConnectionManager Object
        delete ptBCM;
        return FAILURE; 
    }
    else
    {
        return KILL_SIGNAL;
    }
}

int StateMachine::processEventsInTerminateState()
{
    ptBCM->getQueryManagerPointer()->sendWarningtoBro("CTRL+C" 
                        " Signal Received");
    //close broker connection
    ptBCM->closeBrokerConnection();
    // if connection is down then reinitialize all query vectors
    ptBCM->getQueryManagerPointer()->ReInitializeVectors();
    //delete  BrokerConnectionManager Object
    delete ptBCM;
    return SUCCESS;
}

void StateMachine::setNextState(int op_code)
{
    switch(current_state)
    {
        case INIT:
            {
                if(op_code == KILL_SIGNAL)
                    current_state = TERMINATE;
                else if(op_code == SUCCESS)
                    current_state = WAIT_FOR_TOPIC;
                break;
            }
        case WAIT_FOR_TOPIC:
            {
                if(op_code == KILL_SIGNAL)
                    current_state = TERMINATE;
                else if(op_code == SUCCESS)
                    current_state = GET_AND_PROCESS_QUERIES;
                else
                    current_state = INIT;
                break;
            }
        case GET_AND_PROCESS_QUERIES:
            {
                if(op_code == KILL_SIGNAL)
                    current_state = TERMINATE;
                else
                    current_state = INIT;
              break;  
            }
    };
}

int StateMachine::Run()
{    
    //local variable to hold state operation code
    int op_code = 0; 
    do
    {
      switch(current_state)
      {
        case INIT:
        {
            op_code = initializeStateMachine();
            setNextState(op_code);
            break;
        }
        case WAIT_FOR_TOPIC:
        {
            op_code = processEventsInWaitForTopicState();
            setNextState(op_code);
            break;
        }
        case GET_AND_PROCESS_QUERIES:
        {
            op_code = processEventsInGetAndProcessQueriesState();
            setNextState(op_code);
          break;  
        }
        case TERMINATE:
        {
         op_code =  processEventsInTerminateState();
         return op_code;
        }
      };
    }while(!signalHandler->gotExitSignal());
    
    return SUCCESS;                
}
