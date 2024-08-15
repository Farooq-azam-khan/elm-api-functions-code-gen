from typing import Any

import requests
from termcolor import colored

open_api_json_req_url = "http://localhost:8000/openapi.json"
resp = requests.get(open_api_json_req_url)
apis = resp.json()


skip_non_api_routes = True


def add_encoder_to_fn(method_vals, elm_fn_definition_dict):
    args = elm_fn_definition_dict["args"]
    args_names = elm_fn_definition_dict["args_names"]
    elm_request_encoder = ""
    if "requestBody" in method_vals:
        args = ["E.Value"] + args
        args_names = ["request_body_encoder"] + args_names
        elm_request_encoder = (
            "\n        |> HttpBuilder.withJsonBody request_body_encoder"
        )
        # TODO: create encoder based on apis['components']['schemas']
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
    formatted_fn_output = f"""
{elm_fn_definition}
{elm_fn_arguments}
    {elm_route}
        |> HttpBuilder.{method}{elm_request_encoder}
        |> HttpBuilder.withTimeout 90000
        |> HttpBuilder.withExpect
            (Http.expectJson (RemoteData.fromResult >> msg) decoder)
        |> HttpBuilder.request
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
        return elm_route

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
    elm_functions = []
    # elm_functions = {}
    # [{fn_name: str, args_names:[str], args:[str], fn_body: [str], output_arg: str}]
    # fn_body is list of http builder functions
    for route, methods in apis["paths"].items():
        if skip_non_api_routes and not route.startswith("/api"):
            print(f"skipping {route=}")
            continue
        print("-" * 25)
        print(colored(f"{route=}", "yellow"))

        for method, method_vals in methods.items():
            print("keys=", method_vals.keys())
            elm_function_name = method_vals["operationId"]
            elm_fn_definition_dict = {
                "fn_name": elm_function_name,
                "args": ["(WebData a -> msg)", "D.Decoder a"],
                "args_names": ["msg", "decoder"],
                "output_arg": "Cmd msg",
                "fn_body": {
                    "route": '"' + route + '"',
                    "http_method": method,
                    "http_builder_fns": [
                        "\t\t|> HttpBuilder.withTimeout 90000"
                        "\t\t|> HttpBuilder.withExpect\n\t\t\t(Http.expectJson (RemoteData.fromResult >> msg) decoder)"
                        "\t\t|> HttpBuilder.request"
                    ],
                },
            }
            args, args_names, elm_request_encoder = add_encoder_to_fn(
                method_vals, elm_fn_definition_dict
            )
            elm_fn_definition_dict["args"] = args
            elm_fn_definition_dict["args_names"] = args_names
            elm_route, args, args_names = add_url_parameters_to_fn(
                method_vals,
                elm_fn_definition_dict["args"],
                elm_fn_definition_dict["args_names"],
                elm_fn_definition_dict["fn_body"]["route"],
                route,
            )
            elm_fn_definition_dict["fn_body"]["route"] = elm_route

            print(colored(elm_fn_definition_dict, "red"))
            formatted_fn_output = format_api_fn(
                elm_fn_definition_dict,
                method,
                elm_request_encoder,
            )

            if "requestBody" in method_vals:
                print("requestBody=", method_vals["requestBody"])

            if "responses" in method_vals:
                happy_path = method_vals["responses"]["200"]
                print("\tresponses=")
                happy_path_response_schema = happy_path["content"]["application/json"][
                    "schema"
                ]
                print(
                    "\t",
                    f"200 schemas={len(happy_path_response_schema.keys())}",
                    happy_path,
                )
                if len(happy_path_response_schema.keys()) == 0:
                    print(colored("HELP: define response schema", "yellow"))

                # TODO: consider non happy path
                # for resp_key, resp_val in method_vals['responses'].items():
                #     print('\t', resp_key, resp_val)

            print(colored(formatted_fn_output, "green"))
            elm_functions.append(formatted_fn_output)
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


def write_http_fns_file(output_file):
    print(colored("writing file", "green"))
    elm_functions = create_api_functions(apis)
    print(colored(f"writing {len(elm_functions)} api functions", "green"))
    functions_str = "\n\n".join(elm_functions)
    file_content = f"""
module ApiGen exposing(..)

import Http
import HttpBuilder
import Json.Decode as D
import Json.Encode as E
import RemoteData exposing (RemoteData(..), WebData)

{functions_str}
    """.strip()

    with open(output_file, "w") as f:
        f.write(file_content)


if __name__ == "__main__":
    try:
        write_http_fns_file(output_file="./codegen/ApiGen.elm")
        # write_encoders(apis)
    except requests.exceptions.ConnectionError:
        print(f"is {open_api_json_req_url} running?")
