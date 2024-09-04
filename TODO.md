# TODO
* parse `apis['components']['schemas']` into elm type aliases 
    * need to topologically sort the types
    * generate the types afterwards 
    * generated types can have encoder and decoder 
    * these encoder and decoder will be used in conjuction with api functions. 
* create an example directory with a very complex and thourough api backend
    * example 1: cat facts api file (https://github.com/openapi-ts/openapi-typescript/blob/main/packages/openapi-fetch/examples/nextjs/lib/api/v1.d.ts)
    * other examples: https://github.com/OAI/OpenAPI-Specification/tree/main/examples
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

* figure out if the current code is better than the code below 
```elm 
-- api actions 
type ApiActions 
    = NoOp 
    | MODE_API_MODE_GET (FastApiWebData String) 
    | Test_optional_vs_default_api_test_optional_post (FastApiWebData ApiOptionalTest)
    -- | ...

-- api types 
type alias ApiOptionalTest =
    { a_req_type: String
    , a_def_type: String
    , an_optional_type: Maybe (String)
    }

-- api encoders 
api_optionaltest_encoder : ApiOptionalTest -> E.Value
api_optionaltest_encoder ta = 
     E.object 
        [ ("a_req_type", E.string ta.a_req_type)
        , ("a_def_type", E.string ta.a_def_type)
        , ("an_optional_type", maybe_encoder (E.string) ta.an_optional_type)
        ]
-- ...

-- api decoder 
api_optionaltest_decoder : D.Decoder ApiOptionalTest
api_optionaltest_decoder = 
     D.succeed ApiOptionalTest
        |> JDP.required "a_req_type" (D.string)
        |> JDP.required "a_def_type" (D.string)
        |> JDP.required "an_optional_type" (D.nullable D.string)
-- ... 

-- api functions 
test_optional_vs_default_api_test_optional_post : ApiOptionalTest  -> Cmd ApiActions
test_optional_vs_default_api_test_optional_post req_body =
    "/api/test/optional"
        |> HttpBuilder.post
        |> HttpBuilder.withJsonBody (api_optionaltest_encoder req_body)
        |> HttpBuilder.withTimeout 90000
        |> HttpBuilder.withExpect
            (expect_fast_api_response (RemoteData.fromResult >> Test_optional_vs_default_api_test_optional_post) api_optionaltest_decoder)
        |> HttpBuilder.request
-- ... 
mode_api_mode_get : Cmd ApiActions 
mode_api_mode_get =
    "/api/mode"
        |> HttpBuilder.get
        |> HttpBuilder.withTimeout 90000
        |> HttpBuilder.withExpect
            (expect_fast_api_response (RemoteData.fromResult >> MODE_API_MODE_GET) D.string)
        |> HttpBuilder.request
```

vs the following
* no action type 
* more generic function input 
```elm 
-- same encoders and decoders as above 
test_optional_vs_default_api_test_optional_post : ApiOptionalTest -> (FastApiWebData ApiOptionalTest -> msg) -> Cmd msg
test_optional_vs_default_api_test_optional_post req_body msg =
    "/api/test/optional"
        |> HttpBuilder.post
        |> HttpBuilder.withJsonBody (api_optionaltest_encoder req_body)
        |> HttpBuilder.withTimeout 90000
        |> HttpBuilder.withExpect
            (expect_fast_api_response (RemoteData.fromResult >> msg) api_optionaltest_decoder)
        |> HttpBuilder.request

mode_api_mode_get : (FastApiWebData UNKN -> msg) -> Cmd msg
mode_api_mode_get msg =
    "/api/mode"
        |> HttpBuilder.get
        |> HttpBuilder.withTimeout 90000
        |> HttpBuilder.withExpect
            (expect_fast_api_response (RemoteData.fromResult >> msg) D.string)
        |> HttpBuilder.request

```


* usage: 
```elm 
-- Method 1
type GlobalActions = WebServerApiActions ApiActions -- | ...
Cmd.batch 
    [ mode_api_mode_get
    , test_optional_vs_default_api_test_optional_post {a_req_type="asdf",a_def_type="asdf",an_optional_type=Nothing}
    ]
-- will need to map ApiActions type to GlobalActions
case msg of 
    WebServerApiActions api_action -> update_api_actions api_action model -- return (model, Cmd ApiActions)
    -- Other msges 
-- Method 2 
type GlobalActions = CustomAction1 (FastApiWebData String) -- |...
Cmd.batch 
    [ mode_api_mode_get CustomAction1 
    , test_optional_vs_default_api_test_optional_post {a_req_type="asdf",a_def_type="asdf",an_optional_type=Nothing} CustomAction2
    ] 
case msg of 
    CustomAction1 wd -> (model, Cmd.none)
    -- ...
```
