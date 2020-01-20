# Protocols 
Sub-package for the protocols. Each protocol is implemented in its own file. You can see the doc.go for more details about the protocols and how they work. For more formal details, see the theoretical paper mentionned in the main README. 

The general pipeline for a protocol is : 

- `Init` : Initialize the protocol and prepare the structures needed for the protocol. 
- `Start` : Start the protocol (done by the orchestrator in our case always the root). 
- `Dispatch` : This is where the protocol is implemented. First the party will send a wake up message to its children. Then wait for messages from them, perform the aggregation and send it further. 
- `Done` : Here you can finalize the protocol if needed. I did not override the default method here as there was no real benefits to using it. 

Additionally, there is a `Wait` method that will block until the protocol completed the `Dispatch` phase. It is useful to synchronize until it is over. 

In each protocol, there is a detailed explaination of that the dispatch does. 

There is a subdirectory `test` containing all the tests. 