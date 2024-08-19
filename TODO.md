# TODO
* parse `apis['components']['schemas']` into elm type aliases 
    * need to topologically sort the types
    * generate the types afterwards 
    * generated types can have encoder and decoder 
    * these encoder and decoder will be used in conjuction with api functions. 
* create an example directory with a very complex and thourough api backend 
    * uses basic get 
    * uses get with query parameters 
    * uses post 
    * has auth routes 
    * put requests 
    * advanced validation 
* create better input into elm api function i.e. 
    * `E.Value` is too generic and is not helpful. 
    * `msg` type can be removed if an action type is created e.g. `type ApiAction a = RecordUserInput (FastApiWebData a)`
    * `D.Decoder value` argument can potentially be eliminated as well. 

* potential failures / test cases not addressed
    * input query parameters into api function 
    * in python backend, user does not have a type parameter for the input (encoder is left ambiguous)

* how should warnings and errors be address?
    * provide warning and still generate code or error out and tell user to fix api backend? (if user is not incharge of backend then it will be pretty hard to do so)
    * currently if there is no response output user is warned of it. 
    * best option is to provide toggle to do strict or lax. (strict will be on by default and a warning will be given if strict is turned off)
    * elm fashion, be as safe, helpful, and secure as possible. 
