# Gossip Package
## types.go
- `Gossip_Context_Init`: initializes a new GossiperContext object with the given configuration and storage ID.
- `InitializeGossiperContext`: initializes a new GossiperContext object with the given paths to public, private, and crypto configurations, and the given storage ID.
- `CountStorage`: counts the number of objects in a Gossip_Storage and stores the results in a GossiperLogEntry.
- `SaveStorage`: saves the storage object to the value in c.StorageFile.
- `WipeStorage`: wipes all temporary data stored in the context.
- `StoreObject`: stores a gossip object in the appropriate storage based on its type.
- `GetObject`: retrieves a gossip object from storage by its ID.

## gossip_object.go
Gossip Package
This package provides functionality for sending and verifying gossip messages between different entities in a network.

### Constants
- `CTNG_APPLICATION`: The only valid application type for the gossip messages.
- `STH`: Identifier for STH (Signed Tree Head) gossip message type.
- `REV`: Identifier for REV (Revocation) gossip message type.
- `ACC`: Identifier for ACC (Accepted Certificate Chain) gossip message type.
- `CON` : Identifier for CON (Certificate Transparency Object) gossip message type.
- `STH_FRAG`: Identifier for STH gossip message type signed by key frag.
- `REV_FRAG`: Identifier for REV gossip message type signed by key frag.
- `ACC_FRAG`: Identifier for ACC gossip message type signed by key frag.
- `CON_FRAG`: Identifier for CON gossip message type signed by key frag.
- `STH_FULL`: Identifier for STH gossip message type with Aggregated TSS sig.
- `REV_FULL`: Identifier for REV gossip message type with Aggregated TSS sig.
- `ACC_FULL`: Identifier for ACC gossip message type with Aggregated TSS sig.
- `CON_FULL`: Identifier for CON gossip message type with Aggregated TSS sig.
### Functions
- `TypeString`: This function returns the name string of a gossip message type.
- `EntityString`:This function returns the name string of an entity given its URL.
- `GetCurrentTimestamp`:This function returns the current timestamp in RFC3339 format.
- `GetCurrentPeriod`: This function returns the current period based on Maximum Merge Delay (default 1 min).
- `Getwaitingtime` :This function returns the time in seconds until the beginning of the next period.
- `GetID()`:This function returns the ID of a gossip object.
-  `Verify`:This function verifies a gossip object based on its type.
### Types
#### Gossip_object
This type represents a gossip message. It has the following fields:
- `Application`: The application type. Should be set to CTNG_APPLICATION.
- `Period`: The period of the gossip message.
- `Type`: The type of the gossip message. Should be one of the constants defined in the package.
- `Signer`: The URL of the signer of the gossip message.
- `Signers`: A map of signer indexes to URLs.
- `Signature`: An array of two strings representing the signature.
- `Timestamp`: The timestamp of the gossip message in RFC3339 format.
- `Crypto_Scheme`: The cryptographic scheme used to sign the gossip message.
- `Payload`: An array of three strings representing the payload of the gossip message.
#### Gossip_ID 
This type is used as the key to the Gossip_Storage
It has the following fields:
- `Period`: The period of the gossip message.
- `Type`: The type of the gossip message.
- `Entity_URL`: The URL of the entity that sent the gossip message.
#### Gossip_Storage
This type is a map that stores gossip objects by gossip ID

#### Gossip_ID_Counter
same as Gossip_ID with an extra field
- `Signer`: Signer of the gossip message, this is field is necessary for duplication check
#### Gossip_Storage_Counter
This type is a map that stores gossip objects by gossip id counter

## gossiper.go
- `bindContext`: Binds the context to the functions passed to the router.
- `handleRequests`: Handles HTTP requests and routes them to the appropriate function.
- `homePage`: Serves the base page for the gossiper.
- `handleGossip`: Handles POST requests sent to /gossip/push-data.
- `Check_conflicts_and_poms`: Checks for conflicts and PoMs (proof of misbehavior) before storing or gossiping an object.
- `Handle_CON`: Handles objects of type CON (proof of misbehavior).
- `Handle_Sign_and_Gossip`: Signs and gossips objects of type STH (signed tree head) and REV (revocation information).
- `Handle_ACC`: Handles objects of type ACC (accusations).
- `Handle_Frag`: Handles object with signature from one gossiper (sig-frag) aka objects of type STH_FRAG, REV_FRAG, ACC_FRAG, and CON_FRAG.
- `Handle_FULL`: Handles objects with aggregated threshold signature aka objects of type STH_FULL, REV_FULL, ACC_FULL, and CON_FULL.
- `GossipData`: Sends a gossip object to all connected gossipers. 
- `Gossip_NUM_type`:This function is similar to GossipData but is specific to gossip objects of type NUM..
- `SendToOwner`:This function sends a Gossip_object or NUM_FULL to the owner of the gossiper. 
-  `DetectConflicts`: This function processes a duplicate gossip object to check for conflicts. It checks if the two objects have the same type, period, and signer but different signatures. If there is a conflict, it generates a CON (Proof of Misbehavior for conflicting object) and sends it to the owner of the gossiper. It then stores the PoM object and sends it to all connected gossipers.

- `Process_TSS_Object`:
This function processes a TSS (Threshold Signature Scheme) object. It extracts the signature fragment and stores it along with the other fragments in the object's entry in the TSS database. If enough fragments are collected to reach the threshold, the function aggregates the fragments and generates a TSS_FULL object. It then stores and sends the object to the owner of the gossiper.

- `PeriodicTasks`: 
This function is called periodically to perform tasks related to the gossiper. It runs every MMD (Maximum Message Delay) seconds and prints the current period. It then saves and wipes the storage to ensure that only relevant objects are kept in the storage.

- `InitializeGossiperStorage`:
This function initializes the storage directory and file for the gossiper.

- `StartGossiperServer`:
This function starts the HTTP server for the gossiper. It creates an HTTP client and starts the periodic tasks function in a separate thread. It then calls the handleRequests function to start the server.

## num_pom.go
### Types:
- `NUM`: Represents a Monitor Signed Number of PoMs for the given periods that contains several fields, including number of conflicting PoMs, number of Accusation PoMs, a period, a signer monitor, a crypto scheme and a signature.
- `NUM_FRAG`: Represents a Gossiper Signed NUM object, only difference is the signer and signature from NUM
- `NUM_FULL`: Represents a TSS signed NUM object
- `NUM_Counter`: A struct that stores information related to all 3 types above.
### Functions: 
- `NUM_Counter_Init`: Initializes a new NUM_Counter object.
- `Add_NUM`: Adds a numeric object or fragment to the NUM_Counter object.
- `Get_NUM`: Retrieves the number of NUM or NUM_FRAG with the specified parameters.
- `Clear`: Clears the NUM_Counter object.
- `Verify`: Verifies the signature of NUM, NUM_FRAG or NUM_FULL
- `Generate_NUM_FRAG`: Generates a NUM_FRAG from a NUM and a cryptographic configuration.
- `Generate_NUM_FULL`: Generates a NUM_FULL from a list of NUM_FRAGS and a cryptographic configuration.
- `IsDuplicateNUM`: Determines whether a NUM or NUM_FRAG
- `Need_More_NUM_FRAG`: Determines whether more NUM_FRAGS are needed.
- `handleNUM`: Handles a POST request containing a NUM.
- `handleNUM_FRAG`: Handles a POST request containing a NUM_FRAG.
- `handleNUM_FULL`: Handles a POST request containing a NUM_FULL.
