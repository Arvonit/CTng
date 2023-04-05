# Package Monitor
## types.go
This file contains the data types and functions used by the Monitor package. The data types include:

- `MonitorConfig`: A struct that holds the configuration data for a Monitor, including public and private configurations, cryptographic configurations, and more.
- `MonitorContext`: A struct that represents the context of a Monitor. It includes various fields such as a HTTP client, configuration data, gossip storages, and more.
- `GetObjectNumber`: A function that returns the number of objects stored in a specific gossip storage.
- `Clean_Conflicting_Object`: A function that removes STHs and REVs from their respective storages if a Conflict PoM is present.
- `SaveStorage`: A function that saves the ClientUpdate data to a JSON file in the storage directory.
- `LoadOneStorage`: A function that loads a specific gossip storage from a JSON file.
- `GetObject`: A function that returns a specific gossip object based on its ID.
- `IsDuplicate`: A function that checks if a gossip object is a duplicate of an existing object.
- `StoreObject`: A function that stores a gossip object in the appropriate storage.
- `WipeStorage`: A function that removes all temporary data from the storages.
- `InitializeMonitorStorage`: A function that initializes the storage directory for the Monitor.
- `CleanUpMonitorStorage`: A function that deletes all files in the storage directory.
- `InitializeMonitorContext`: A function that initializes the context for a Monitor.
- `GenerateMonitorConfigTemplate`: A function that generates a configuration template for a Monitor.

## monitor.go
The file mcontains functions and logic that relate to the Monitor component of the CTng project.
- `receiveGossip`: This function receives a gossip message sent to the monitor, processes the message, and stores it for later use.
- `handle_gossip_from_gossiper`: This function handles a gossip message sent from a gossiper and processes it.
- `handle_gossip`: This function handles a gossip message and verifies that the message is valid. If the message is valid, it processes it.
- `handle_num_full`: This function handles the receipt of a NUM_FULL gossip message and stores it in the Storage_NUM_FULL variable of the MonitorContext struct.
- `QueryLoggers`: This function queries all of the loggers specified in the configuration file and stores the returned STH gossip messages in the MonitorContext struct.
- `QueryAuthorities`: This function queries all of the CAs specified in the configuration file and stores the returned revocation gossip messages in the MonitorContext struct.
- `AccuseEntity`: This function creates an accusation gossip message and sends it to the gossiper.
- `Send_to_gossiper`: This function sends a gossip message to the gossiper.
- `Send_POM_NUM_to_gossiper`: This function sends a PoM_NUM message to the gossiper.
- `Check_entity_pom`: This function checks if an entity has a proof of misbehavior (PoM) on file for the current period.
- `IsLogger`: This function checks if a given entity URL is a logger.
- `IsAuthority`: This function checks if a given entity URL is a CA.
- `GenerateUpdate`: This function generates a client update object for a given period.
- `PeriodicTasks`: This function performs periodic tasks for the monitor component of the CTng project, including querying loggers and CAs, cleaning up conflicting objects, and generating client updates.

## client-update-monitor.go
- `PrepareClientUpdate`: This function takes a MonitorContext and a file path as inputs, reads the contents of the file located at the file path, and unmarshals the contents into a ClientUpdate struct. The function returns a pointer to the ClientUpdate struct and an error.
- `requestupdate`: This function takes a MonitorContext, an http.ResponseWriter, and an http.Request as inputs, decodes the contents of the request body into a string, uses the string to generate a file path to a ClientUpdate JSON file, prepares a ClientUpdate object from the file using PrepareClientUpdate, marshals the object into a JSON string, and encodes the string as the response to the HTTP request. The function does not return anything.

## monitor-server.go
- `bindMonitorContext`:This function is used to handle HTTP requests.

- `handleMonitorRequests`: This function sets up the HTTP server to handle incoming requests for the monitor. It uses the Gorilla mux router to route incoming requests to their corresponding functions.

- `StartMonitorServer`: This function starts the monitor, setting up an HTTP client, and then starting the HTTP server loop to handle incoming requests. It also starts a new goroutine to handle tasks that must occur periodically.

## monitor-test.go
- `testReceiveGossip`: This function tests the receiveGossip function, which receives gossip objects from a gossiper.
- `testPanicOnBadReceiveGossip`: This function tests if the receiveGossip function panics when it receives a bad request.
- `testPrepareClientupdate`: This function tests the PrepareClientUpdate function, which reads a client update from a file path.
- `testLoadStorage`: This function tests the LoadOneStorage function, which loads a single storage file into the storage map of the monitor context.
- `testSaveStorage`: This function tests the SaveStorage function, which saves the current state of the storage map of the monitor context to a storage file.
- `testMonitorServer`: This function tests the StartMonitorServer function, which starts the HTTP server for the monitor context.
-  `TestNUM`:  function tests the NUM struct and its related functions in the gossip package.
