from typing import Any

import requests
from termcolor import colored

local_openapi_json = "http://localhost:8000/openapi.json"


def get_openapi_config(
    open_api_json_req_url: str = local_openapi_json,
) -> dict[Any, Any]:
    resp = requests.get(open_api_json_req_url)
    apis = resp.json()
    return apis


skip_non_api_routes = True
# use_fast_api_web_data = True # TODO toggle fastapi webdata
tab = "    "


def add_encoder_to_fn(method_vals, elm_fn_definition_dict):
    args = elm_fn_definition_dict["args"]
    args_names = elm_fn_definition_dict["args_names"]
    elm_request_encoder = ""
    if "requestBody" in method_vals:
        print("requestBody=", method_vals["requestBody"])
        args = ["E.Value"] + args
        args_names = ["request_body_encoder"] + args_names
        elm_request_encoder = (
            f"{tab}{tab}|> HttpBuilder.withJsonBody request_body_encoder"
        )
    return args, args_names, elm_request_encoder


def format_api_fn(
    elm_fn_definition_dict,
    method,
    elm_request_encoder,
):
    elm_fn_definition = f'{elm_fn_definition_dict["fn_name"]} : {" -> ".join(elm_fn_definition_dict["args"])} -> {elm_fn_definition_dict["output_arg"]}'
    elm_fn_arguments = f'{elm_fn_definition_dict["fn_name"]} {" ".join(elm_fn_definition_dict["args_names"])} ='
    elm_route = elm_fn_definition_dict["fn_body"]["route"]
    method = elm_fn_definition_dict["fn_body"]["http_method"]

    elm_fn_body_http_fns = "\n".join(
        elm_fn_definition_dict["fn_body"]["http_builder_fns"]
    )
    formatted_fn_output = f"""
{elm_fn_definition}
{elm_fn_arguments}
{tab}{elm_route}
{tab}{tab}|> HttpBuilder.{method}
{elm_fn_body_http_fns}
""".strip()
    return formatted_fn_output


def add_url_parameters_to_fn(
    method_vals,
    args,
    args_names,
    elm_route,
    route,
):
    if "parameters" not in method_vals:
        return elm_route, args, args_names

    parameters = method_vals["parameters"]
    route_path = route.split("/")
    print(f"\tparameters (total={len(parameters)}):", parameters)
    for rp in route_path:
        if "{" in rp and "}" in rp:
            for url_param in parameters:
                print(f"{url_param=}")
                if url_param["in"] == "path":
                    if rp.replace("{", "").replace("}", "") == url_param["name"]:
                        elm_route = elm_route.replace(
                            rp, f"\"++ {url_param['name']} ++\""
                        )
                        args = ["String"] + args
                        args_names = [url_param["name"]] + args_names
    elm_route = elm_route.replace('++""', "").strip()
    return elm_route, args, args_names


def create_response_type(method_vals):
    if "responses" in method_vals:
        responses = method_vals["responses"]
        print(f"responses ({len(responses.keys())})=")
        for resp_key, resp_val in method_vals["responses"].items():
            print(colored(f"\t{resp_key}={resp_val}", "yellow"))
            if "content" in resp_val:
                response_content_schema = resp_val["content"]["application/json"][
                    "schema"
                ]
                schemas_count = len(response_content_schema.keys())
                if schemas_count == 0:
                    print(
                        colored(
                            "\tWARN: schema response not defined",
                            "yellow",
                        )
                    )


def create_api_functions(apis: dict[Any, Any]):
    print(colored("Assuming everyting is content-type: application/json", "red"))
    print(
        colored(
            "Assuming elm http builder methods and openapi http methods are one-to-one",
            "red",
        )
    )
    print(colored("Assume url param name is a valid elm variable", "red"))
    # TODO: create a dict that stores function name.
    # TODO: if there is a duplicate then make sure to tell user and add random 4 letter digit to it at the end.
    # elm_functions = []
    elm_functions = {}
    # [{fn_name: str, args_names:[str], args:[str], fn_body: [str], output_arg: str}]
    # fn_body is list of http builder functions
    for route, methods in apis["paths"].items():
        if skip_non_api_routes and not route.startswith("/api"):
            print(f"skipping {route=}")
            continue
        print("-" * 25)
        print(colored(f"{route=}", "yellow"))

        for method, method_vals in methods.items():
            operation_id = method_vals["operationId"]
            print(colored(f"{operation_id=} ", "yellow"))
            print("keys=", method_vals.keys())
            elm_fn_definition_dict = {
                "fn_name": operation_id,
                "args": ["(FastApiWebData a -> msg)", "D.Decoder a"],
                "args_names": ["msg", "decoder"],
                "output_arg": "Cmd msg",
                "fn_body": {
                    "route": '"' + route + '"',
                    "http_method": method,
                    "http_builder_fns": [
                        f"{tab}{tab}|> HttpBuilder.withTimeout 90000",
                        f"{tab}{tab}|> HttpBuilder.withExpect\n{tab}{tab}{tab}(expect_fast_api_response (RemoteData.fromResult >> msg) decoder)",
                        f"{tab}{tab}|> HttpBuilder.request",
                    ],
                },
            }
            args, args_names, elm_request_encoder = add_encoder_to_fn(
                method_vals, elm_fn_definition_dict
            )
            if len(elm_request_encoder) > 0:
                elm_fn_definition_dict["fn_body"]["http_builder_fns"].insert(
                    0, elm_request_encoder
                )
            elm_fn_definition_dict["args"] = args
            elm_fn_definition_dict["args_names"] = args_names
            elm_route = elm_fn_definition_dict["fn_body"]["route"]

            elm_route, args, args_names = add_url_parameters_to_fn(
                method_vals,
                elm_fn_definition_dict["args"],
                elm_fn_definition_dict["args_names"],
                elm_route,
                route,
            )
            elm_fn_definition_dict["fn_body"]["route"] = elm_route

            # print(colored(elm_fn_definition_dict, "red"))
            formatted_fn_output = format_api_fn(
                elm_fn_definition_dict,
                method,
                elm_request_encoder,
            )
            create_response_type(method_vals)

            print(colored(formatted_fn_output, "green"))
            if elm_fn_definition_dict["fn_name"] in elm_functions:
                print(
                    colored(f'ERR: {elm_fn_definition_dict["fn_name"]} already exists')
                )
            elm_functions[elm_fn_definition_dict["fn_name"]] = formatted_fn_output
    return elm_functions


python_type_to_elm_encoder_type = {
    "string": "E.string",
    "array": "E.list TODO:ref_encoder",
    "boolean": "E.bool",
    "integer": "E.int",
    "number": "E.float",
}


def write_encoders(apis):
    encoder_fns = []
    for tpe, tpe_props in apis["components"]["schemas"].items():
        if tpe_props["type"] == "object":
            elm_properties = []
            print("-" * 25)
            print(colored(tpe, "red"))
            print(f"{tpe_props.keys()=}")
            if "required" in tpe_props:
                print(f'required={tpe_props["required"]}')
            print(f'title={tpe_props["title"]}')
            print("properties:", tpe_props["properties"])
            for prop_name, prop_type in tpe_props["properties"].items():
                if "type" in prop_type:
                    python_type = prop_type["type"]
                    if python_type == "array":
                        if "items" in prop_type:
                            print(colored(prop_type["items"], "yellow"))
                    else:
                        encoder_type = python_type
                        if python_type not in python_type_to_elm_encoder_type:
                            print(
                                colored(
                                    f"{python_type} not in python_type_to_elm_encoder_type",
                                    "red",
                                )
                            )
                        else:
                            encoder_type = python_type_to_elm_encoder_type[python_type]
                        elm_prop_tupe_str = f'("{prop_name}", {encoder_type} TODO:VAR)'
                else:
                    elm_prop_tupe_str = (
                        f'("{prop_name}", {encoder_type} TODO:ref_encoder)'
                    )

                elm_properties.append(elm_prop_tupe_str)
            elm_schema_encoder_str = f""" 
dummy_encoder : E.Value
dummy_encoder = E.object [{", ".join(elm_properties)}]
""".strip()
            print(colored(elm_schema_encoder_str, "green"))
    return encoder_fns


"""
(E.object [ ( "query", E.string query ) ]
{'properties': {'query': {'type': 'string', 'title': 'Query'}}, 'type': 'object', 'required': ['query'], 'title': 'DBQuery'}
class DBQuery(BaseModel):
    query: str
"""

elm_expect_fastpai_fn_and_types = """
type FastApiHttpError
    = BadUrl String
    | Timeout
    | NetworkError
    | BadStatus Int ValidationError
    | BadBody String

type alias FastApiWebData a =
    RemoteData FastApiHttpError a



type LocType
    = StringLoc String
    | IntLoc Int


type alias ValidationError =
    { detail : List ValidationErrorDetail }


type alias ValidationErrorDetail =
    { loc : List LocType, msg : String, type_ : String }


loc_decoder : D.Decoder LocType
loc_decoder =
    D.oneOf [ D.string |> D.map StringLoc, D.int |> D.map IntLoc ]


decode_validation_error : D.Decoder ValidationError
decode_validation_error =
    D.map ValidationError
        (D.field "detail" (D.list decode_ValidationErrorDetail))


decode_ValidationErrorDetail : D.Decoder ValidationErrorDetail
decode_ValidationErrorDetail =
    D.map3 ValidationErrorDetail
        (D.field "loc" (D.list loc_decoder))
        (D.field "msg" D.string)
        (D.field "type" D.string)


expect_fast_api_response : (Result FastApiHttpError value -> msg) -> D.Decoder value -> Http.Expect msg
expect_fast_api_response to_msg decoder =
    Http.expectStringResponse
        to_msg
        (\response ->
            case response of
                Http.BadUrl_ url ->
                    Err <| BadUrl url

                Http.Timeout_ ->
                    Err <| Timeout

                Http.NetworkError_ ->
                    Err <| NetworkError

                Http.BadStatus_ metadata str_body ->
                    Err <|
                        BadStatus metadata.statusCode <|
                            case D.decodeString decode_validation_error str_body of
                                Ok value ->
                                    value

                                Err err ->
                                    { detail = [ { loc = [], msg = D.errorToString err, type_ = "" } ] }

                Http.GoodStatus_ _ str_body ->
                    case D.decodeString decoder str_body of
                        Ok value ->
                            Ok value

                        Err err ->
                            Err (BadBody (D.errorToString err))
        )
""".strip()

elm_imports = """
import Http
import HttpBuilder
import Json.Decode as D
import Json.Encode as E
import RemoteData exposing (RemoteData(..))
""".strip()


def write_http_fns_file(
    elm_functions: list[Any], output_file: str, open_api_version: str
) -> None:
    print(colored("writing file", "green"))
    print(colored(f"writing {len(elm_functions)} api functions", "green"))
    functions_str = "\n\n".join(
        [elm_fn_formatted for _, elm_fn_formatted in elm_functions.items()]
    )
    file_content = f"""
module ApiGen exposing(..)
-- GENRATED FOR OPENAPI={open_api_version}

{elm_imports}

{elm_expect_fastpai_fn_and_types}

{functions_str}
    """.strip()

    with open(output_file, "w") as f:
        f.write(file_content)


if __name__ == "__main__":
    try:
        open_api_json_req_url = local_openapi_json
        apis = get_openapi_config(open_api_json_req_url)
        elm_functions = create_api_functions(apis)
        write_http_fns_file(
            elm_functions,
            output_file="./codegen/ApiGen.elm",
            open_api_version=apis["openapi"],
        )
    except requests.exceptions.ConnectionError:
        print(f"is {open_api_json_req_url} running?")
