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

#pragma once


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


/**
 * enum for possible states in extension
 * 
 * INIT -- Read broker.ini and connect to master
 * WAIT_FOR_TOPIC = waiting for group topic
 * GET_AND_PROCESS_QUERIES = get SQL queries and then process them and send 
 * update to master
 * TERMINATE = when kill signal is received
 */
enum State {INIT, WAIT_FOR_TOPIC,GET_AND_PROCESS_QUERIES,TERMINATE};

/*enum Event {CONNECTION_ESTABLISHED_EVENT,CONNECTION_BROKEN_EVENT, 
            SIG_KILL_EVENT, PARAM_READ_EVENT, TOPIC_RECEIVED_EVENT, 
            HOST_SUBSCRIBE_EVENT, HOST_UNSUBSCRIBE_EVENT
            };*/
// To hold the current state
static State current_state;

class StateMachine
{
private:
    // BrokerConnectionManager class pointer
  BrokerConnectionManager* ptBCM;
  // to store  the return values of BrokerQueryManager functions and
  // use it for comparison purpose
  bool processResponse;
  // flag to check whether broker.ini is read or not
  int fileResponse;
  //connection response
  bool connectionResponse;
  //to store getandSetTopic response 
  int topicResponse;
  //FileReader Class Object
  FileReader fileReader;
  //SignalHandler object to trace kill signal
  SignalHandler *signalHandler;
  
private:
    /**
     * @brief To process the tasks in INIT state
     * @return returns operation code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int initializeStateMachine();
    
    /**
     * @brief To process the tasks in WAIT_FOR_TOPIC state
     * 
     * @return returns operation code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int processEventsInWaitForTopicState();
    
    /**
     * @brief To process the tasks in GET_AND_PROCESS_QUERIES state
     * 
     * @return returns operation code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int processEventsInGetAndProcessQueriesState();
    
    /**
     * @brief To process the tasks in TERMINATE state
     * 
     * @return returns operation code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int processEventsInTerminateState();
    
    /**
     * @brief To find the next state of state machine based on the operation 
     * code form the current state process functions.
     * 
     * @param op_code Current state of state machine
     */
    void setNextState(int op_code);
    
    //std::pair<int,eventQueue*> waitForEvents();
   // bool processEvents(State,Event);
   // void buildAllowedStateTransitionMap();
public:
    
    /**
     * @brief Constructor 
     * To Initialize private member for safe usages
     * 
     * @param signalHandler pointer to signal handler object created in main()
     */
    StateMachine(SignalHandler *handler);
    
    
    /**
     * @brief The main function to operate the state machine. All state
     *  operations with state transitions will be managed in this function.
     * 
     * @return returns operation code. It can be KILL_SIGNAL, SUCCESS or FAILURE
     */
    int Run();
    
};
