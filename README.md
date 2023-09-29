# Gotham-engine
![](https://en.wikipedia.org/wiki/V6_engine#/media/File:IC_engine.jpg)

Gotham engine is the engine for gotham-city project. It abstracts through traits,
routes for keygen and sign in a 2P setting for Lindell17 protocol. The level of abstraction allows
the implementers to pass specific DB api and authorization policies. The engine provides default trait implementations
such that the implementers are only implementing the peripherals. An example of usage is provided in the gotham-city project.
## Workflow for implementers:
1. Instantiate empty traits for KeyGen and Sign:
   `impl KeyGen for PublicGotham {}` 
2. `impl Sign for PublicGotham {}`
2. 
2. 
