from typing import Any

import click
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

def generate_elm_api_function(route: str, method: str, method_vals: dict[Any, Any]) -> dict[Any, Any]:
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
    elm_fn_definition_dict['args'] = args 
    elm_fn_definition_dict['args_names'] = args_names


    return elm_fn_definition_dict

def create_api_functions(apis: dict[Any, Any]):
    print(colored("Assuming everyting is content-type: application/json", "red"))
    print(
        colored(
            "Assuming elm http builder methods and openapi http methods are one-to-one",
            "red",
        )
    )
    print(colored("Assume url param name is a valid elm variable", "red"))
    elm_functions = {}
    for route, methods in apis["paths"].items():
        if skip_non_api_routes and not route.startswith("/api"):
            print(f"skipping {route=}")
            continue
        print("-" * 25)
        print(colored(f"{route=}", "yellow"))

        for method, method_vals in methods.items():
            elm_fn_definition = generate_elm_api_function(route, method, method_vals)
            formatted_fn_output = format_api_fn(
                elm_fn_definition,
                method,
                "",
            )
            create_response_type(method_vals)

            print(colored(formatted_fn_output, "green"))
            if elm_fn_definition["fn_name"] in elm_functions:
                print(
                    colored(f'ERR: {elm_fn_definition["fn_name"]} already exists')
                )
            elm_functions[elm_fn_definition["fn_name"]] = formatted_fn_output
    return elm_functions


python_type_to_elm_encoder_type = {
    "string": "E.string",
    "array": "E.list TODO:ref_encoder",
    "boolean": "E.bool",
    "integer": "E.int",
    "number": "E.float",
}


def write_encoders(apis):
    encoder_fns = {}
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
        (\\response ->
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

maybe_encoder_fn = '''
maybe_encoder : (a -> E.Value) -> Maybe a -> E.Value 
maybe_encoder value_encoder mv = 
    case mv of 
        Just v -> value_encoder v 
        Nothing -> E.null 
'''.strip()
def write_http_fns_file(
        elm_functions: list[Any], 
        elm_types: list[str]=[], 
        elm_encoder_fns: list[str]=[], 
        output_file: str='./codegen/ApiGen.elm', open_api_version: str='3.1.0', info:dict={}
) -> None:
    print(colored("writing file", "green"))
    print(colored(f"writing {len(elm_types)} api types", "blue"))
    print(colored(f"writing {len(elm_encoder_fns)} encoder functions", "blue"))
    print(colored(f"writing {len(elm_functions)} api functions", "blue"))
    print(colored(f'Total = {len(elm_types)+len(elm_encoder_fns)+len(elm_functions)}', 'blue'))
    functions_str = "\n\n".join(
        [elm_fn_formatted for _, elm_fn_formatted in elm_functions.items()]
    )
    
    unknown_type = 'type alias UNKN=String' 
    elm_types_str = unknown_type +'\n\n' + '\n\n'.join(elm_types)
    elm_encoder_fns_str = "\n\n".join(elm_encoder_fns)
    file_content = f"""
module ApiGen exposing(..)
-- GENRATED FOR OPENAPI={open_api_version}
-- INFO={info}

{elm_imports}

-- Helper Fns 
{maybe_encoder_fn}

-- Api Types
{elm_types_str}

-- Api Encoder Fns 
{elm_encoder_fns_str}

-- Api Functions
{elm_expect_fastpai_fn_and_types}

{functions_str}
    """.strip()



    with open(output_file, "w") as f:
        f.write(file_content)


# TODO: add argument for output file path
# TODO: add strict argument with default being true  and a warning stating: "only disable if you do not control your backend code"
@click.group()
def cli():
    pass


@click.command()
@click.option(
    "-u",
    "--url",
    default=local_openapi_json,
    type=str,
    help=f"Location of the openapi.json file (e.g. {local_openapi_json})",
)
def write_elm_fns(url):
    try:
        apis = get_openapi_config(url)
        elm_functions = create_api_functions(apis)
        write_http_fns_file(
            elm_functions,
            output_file="./codegen/ApiGen.elm",
            open_api_version=apis["openapi"],
        )
        return apis, elm_functions
    except requests.exceptions.ConnectionError:
        print(f"is {url} running?")


def main():
    cli.add_command(write_elm_fns)
    cli()

def convert_to_elm_encoder_type(json_type: str): 
    if json_type == 'string': 
        return 'E.string' 
    elif json_type == 'integer': 
        return 'E.int'
    elif json_type == 'boolean': 
        return 'E.bool' 
    elif json_type == 'float' or json_type == 'number':
        return 'E.float'
    elif json_type == 'array': 
        return 'E.list (E.string)'
    return 'E.string "UNKN"' 


def convert_to_elm_data_type(json_type: str): 
    if json_type == 'string': 
        return 'String' 
    elif json_type == 'integer': 
        return 'Int'
    elif json_type == 'boolean': 
        return 'Bool' 
    elif json_type == 'float' or json_type == 'number':
        return 'Float'
    elif json_type == 'array': 
        return 'List UNKN'
    return 'UNKN' 

elm_reserved_keywards = {'and', 'as', 'case', 'else', 'if', 'in', 'let', 'of', 'then', 'type', 'where', 'with', 'module', 'import', 'exposing', 'port', 'effect', 'command', 'subscription', 'program'}
open_bracket, close_bracket = '(', ')'
def generate_elm_prop_name(prop_name):
    if prop_name in elm_reserved_keywards:
        return f'{prop_name}_'
    return prop_name 

# e.g. List String
# e.g. List (List String) or List (List (String))
def recursive_type_gen(items, prefix):
    if items['type'] == 'array': 
        return recursive_type_gen(items['items'], prefix=prefix+f'List {open_bracket}') + close_bracket
    
    elm_prop_type = convert_to_elm_data_type(items["type"])
    return f'{prefix} {elm_prop_type} {close_bracket}'

def elm_encoder_recursive_type_gen(items, prefix):
    print(colored(f'{items}', 'red'))
    if 'type' not in items: 
        return ''
    if items['type'] == 'array': 
        return elm_encoder_recursive_type_gen(items['items'], prefix = prefix + f'E.list {open_bracket}') + close_bracket
    elm_encoder_type = convert_to_elm_encoder_type(items['type'])
    return f'{prefix} {elm_encoder_type} {close_bracket}'

def generate_encoder(elm_t_name, elm_t_props, elm_t_union_types):
    print(elm_t_props)
    encoder_fn_def = {'fn_name': f'{elm_t_name.replace(type_prefix, "api_").lower()}_encoder', 'args': [elm_t_name, 'E.Value'], 
                      'args_names': ['v'], 'fn_body': {
                          'encoder_list': [(f'"{elm_prop_name}"',f'E.string v.{elm_prop_name}') for elm_prop_name, _ in elm_t_props.items()]
                            
                          }}
    return encoder_fn_def 

type_prefix = 'Api'
'''
type UT_loc 
    = UTArg0 String 
    | UtArg1 Int 

api_ut_loc_encode : UT_loc -> E.Value
api_ut_loc_encode ut = 
    case ut of 
        UTArg0 s -> E.string s 
        UTArg1 s -> E.int s

'''
def generate_elm_maybe_encoder(type0, type1):
    if type0 == 'null':
        return f'maybe_encoder ({convert_to_elm_encoder_type(type1)})'
    return f'maybe_encoder ({convert_to_elm_encoder_type(type0)})'

def generate_elm_maybe_type(type0, type1):
    if type0 == 'null':
        return f'Maybe ({convert_to_elm_data_type(type1)})'
    return f'Maybe ({convert_to_elm_data_type(type0)})' 

def generate_elm_type_and_encoder_fn(schema: dict[str, Any]) -> str: 
    all_elm_union_types = [] 
    all_elm_union_encoders = [] 

    print(colored(f'schema keys={schema.keys()}', 'yellow'))
    print(colored(f'required={schema.get("required")}', 'yellow'))
    required = [k for k,_ in schema['properties'].items()]
    if 'required' in schema: 
        required = schema['required']
    required = set(required) 

    elm_type_args_dict = {}
    elm_type_name = f'{type_prefix}{schema["title"]}'
    elm_encoder_fn_def = {
        'fn_name': f'{elm_type_name.replace(type_prefix, "api_").lower()}_encoder', 
        'args': [elm_type_name], 
        'encoder_type': 'type_alias', 
        'args_output': 'E.Value',
        'args_names': ['ta'], 
        'fn_body': {
         'encoder_list': []
    }}
    
    for prop_name, prop_metadata in schema['properties'].items():
        is_required = prop_name in required
        print(prop_name, '===', prop_metadata)
        elm_prop_name = generate_elm_prop_name(prop_name)
        elm_encoder_tuple = [f'"{prop_name}"', 'E.string "TODO"']
        if 'type' in prop_metadata: 
            prop_type = prop_metadata['type']
            print(f'{prop_type=}')
            elm_prop_type = convert_to_elm_data_type(prop_type)
            elm_encoder_tuple[1] = f'{convert_to_elm_encoder_type(prop_type)} ta.{elm_prop_name}'


            if prop_type == 'array':
                if 'type' in prop_metadata['items']:
                    elm_recursed_type_gen = recursive_type_gen(prop_metadata['items'], prefix=f'List {open_bracket}')
                    elm_rtg_encoder = elm_encoder_recursive_type_gen(prop_metadata['items'], prefix=f'E.list {open_bracket}')
                    #list_type = convert_to_elm_data_type(prop_metadata["items"]["type"])
                    elm_prop_type = elm_recursed_type_gen
                    elm_encoder_tuple[1] = elm_rtg_encoder + f' ta.{elm_prop_name}'
                elif 'anyOf' in prop_metadata['items']:
                    elm_union_type_name = f'UT_{elm_prop_name}'
                    # TODO: implement case expression for ut encoder func
                    ut_encoder_fn = {'fn_name': f'api_{elm_union_type_name.lower()}_encoder', 
                                     'args': [elm_union_type_name], 
                                     'encoder_type': 'union_type', 
                                     'args_output': 'E.Value', 
                                     'args_names': ['ut'], 
                                     'fn_body': {'encoder_list': [f'{tab}case ut of']}
                                     }
                    # TODO: generate a union type and insert it into type array 
                    union_types = [] 
                    for i, ut in enumerate(prop_metadata['items']['anyOf']):
                        if 'type' in ut:
                            elm_ut_arg = convert_to_elm_data_type(ut['type'])
                            union_types.append(f'UTArg{i} {elm_ut_arg}')
                            ut_encoder_fn['fn_body']['encoder_list'].append(f'{tab}{tab}UTArg{i} v -> {convert_to_elm_encoder_type(ut["type"])} v')
                    
                    #print(colored(ut_encoder_fn, 'red'))
                    union_type_gen = f'type {elm_union_type_name}\n{tab}= '
                    union_type_gen += f'\n{tab}| '.join(union_types)
                    print(colored(union_type_gen, 'yellow'))
                    all_elm_union_types.append(union_type_gen)
                    elm_prop_type = f'List {elm_union_type_name}'

                    all_elm_union_encoders.append(ut_encoder_fn)
                   

                    #elm_rtg_encoder = elm_encoder_recursive_type_gen(prop_metadata['items'], prefix=f'E.list {open_bracket}')
                    elm_encoder_tuple[1] = f'E.list {ut_encoder_fn["fn_name"]} ta.{elm_prop_name}'

                    
                elif '$ref' in prop_metadata['items']: 
                    # assume type alias for ref is created - might not even need topological sort - elm compiler could handle it for me
                    reference = prop_metadata['items']['$ref'].split('/')[-1]
                    ref_type_name = f'{type_prefix}{reference}'
                    elm_prop_type = f'List {ref_type_name}'

                    # assume encoder function exists. what is the name? 
                    ref_encoder_fn_name = f'{ref_type_name.replace(type_prefix, "api_").lower()}_encoder' 
                    elm_encoder_tuple[1] = f'E.list ({ref_encoder_fn_name}) ta.{elm_prop_name}'
        elif '$ref' in prop_metadata:
            reference = prop_metadata['$ref'].split('/')[-1]
            ref_type_name = f'{type_prefix}{reference}'
            elm_prop_type = f'{ref_type_name}'
            
            ref_encoder_fn_name = f'{ref_type_name.replace(type_prefix, "api_").lower()}_encoder' 
            elm_encoder_tuple[1] = f'{ref_encoder_fn_name} ta.{elm_prop_name}' 
        elif  'anyOf' in prop_metadata and len(prop_metadata) == 2:
            type0 = prop_metadata['anyOf'][0]['type']
            type1 = prop_metadata['anyOf'][1]['type']
            if (type0 == 'null' or type1 == 'null'):
                # Optional type used 
                #print(colored('generating Optional Type', 'yellow'))
                elm_prop_type = generate_elm_maybe_type(type0, type1) 
                elm_encoder_type = generate_elm_maybe_encoder(type0, type1)
                elm_encoder_tuple[1] = f'{elm_encoder_type} ta.{elm_prop_name}'
            else: 
                print(colored('TODO: account for anyOf length > 2', 'red'))
                elm_prop_type = 'UNKN'
        else: 
            print(f'proptye not found for {prop_name=}') 
            elm_prop_type = 'UNKN' 
        if is_required:
            elm_type_args_dict[elm_prop_name] = elm_prop_type
        else: 
            # TODO: figure out what to do with default values 
            elm_type_args_dict[elm_prop_name] = f'{elm_prop_type}'
        #print(colored(f'{elm_encoder_tuple=}', 'red'))
        elm_encoder_fn_def['fn_body']['encoder_list'].append(elm_encoder_tuple)
    #print(colored(f'{len(all_elm_union_encoders)=}', 'red'))
    return elm_type_name, elm_type_args_dict, all_elm_union_types, elm_encoder_fn_def, all_elm_union_encoders

open_square_bracket, close_square_braket = '[', ']'
def format_elm_encoder_fn(encoder_fn_def):
    fn_args = ' -> '.join(encoder_fn_def['args'])
    fn_args_names = ' '.join(encoder_fn_def['args_names'])
    if encoder_fn_def['encoder_type'] == 'type_alias':
        encoder_list = f'\n{tab}{tab}{open_square_bracket} '+ f'\n{tab}{tab}, '.join([f'({prop_name}, {prop_val})' for prop_name, prop_val in encoder_fn_def['fn_body']['encoder_list']]) 
        encoder_list +=  f'\n{tab}{tab}]'

        return f'''
{encoder_fn_def["fn_name"]} : {fn_args} -> {encoder_fn_def["args_output"]}
{encoder_fn_def["fn_name"]} {fn_args_names} = 
{tab} E.object {encoder_list}
'''.strip()
    
    encoder_list = '\n'.join(encoder_fn_def['fn_body']['encoder_list'])
    return f'''
{encoder_fn_def["fn_name"]} : {fn_args} -> {encoder_fn_def["args_output"]}
{encoder_fn_def["fn_name"]} {fn_args_names} = 
{encoder_list}

    '''.strip()


def generate_elm_type_alias(schema: dict[str, Any]) -> str: 
    all_elm_union_types = [] 
    # TODO: this will need to be a recursive function eventually
    print(colored(f'schema keys={schema.keys()}', 'yellow'))
    print(colored(f'required={schema.get("required")}', 'yellow'))
    required = [k for k,_ in schema['properties'].items()]
    if 'required' in schema: 
        required = schema['required']
    required = set(required) 

    elm_type_args_dict = {}
    for prop_name, prop_metadata in schema['properties'].items():
        is_required = prop_name in required
        print(prop_name, '===', prop_metadata)
        elm_prop_name = generate_elm_prop_name(prop_name)
        if 'type' in prop_metadata: 
            prop_type = prop_metadata['type']
            elm_prop_type = convert_to_elm_data_type(prop_type)

            if prop_type == 'array':
                if 'type' in prop_metadata['items']:
                    elm_recursed_type_gen = recursive_type_gen(prop_metadata['items'], prefix='List (')
                    #list_type = convert_to_elm_data_type(prop_metadata["items"]["type"])
                    elm_prop_type = elm_recursed_type_gen
                elif 'anyOf' in prop_metadata['items']:
                    elm_union_type_name = f'UT_{elm_prop_name}'
                    # TODO: generate a union type and insert it into type array 
                    union_types = [] 
                    for i, ut in enumerate(prop_metadata['items']['anyOf']):
                        if 'type' in ut:
                            elm_ut_arg = convert_to_elm_data_type(ut['type'])
                            union_types.append(f'UTArg{i} {elm_ut_arg}')

                    union_type_gen = f'type {elm_union_type_name}\n{tab}= '
                    union_type_gen += f'\n{tab}| '.join(union_types)
                    all_elm_union_types.append(union_type_gen)
                    elm_prop_type = f'List {elm_union_type_name}'

                    
                elif '$ref' in prop_metadata['items']: 
                    # assume type alias for ref is created - might not even need topological sort - elm compiler could handle it for me
                    reference = prop_metadata['items']['$ref'].split('/')[-1]
                    ref_type_name = f'{type_prefix}{reference}'
                    elm_prop_type = f'List {ref_type_name}'
        elif '$ref' in prop_metadata:
            reference = prop_metadata['$ref'].split('/')[-1]
            ref_type_name = f'{type_prefix}{reference}'
            elm_prop_type = f'{ref_type_name}'
        if is_required:
            elm_type_args_dict[elm_prop_name] = elm_prop_type
        else: 
            elm_type_args_dict[elm_prop_name] = f'Maybe ({elm_prop_type})'
    elm_type_name = f'{type_prefix}{schema["title"]}'
    return elm_type_name, elm_type_args_dict, all_elm_union_types

def format_elm_types(elm_type_name, elm_type_args_dict: dict[str, Any], all_elm_union_types: str) -> str: 

    elm_type_args_tuple = [(k,v) for k,v in elm_type_args_dict.items()]
    first_type_arg = elm_type_args_tuple[0]

    elm_type_args = '{ ' + f'{first_type_arg[0]}: {first_type_arg[1]}\n'
    if len(elm_type_args_tuple) >= 2:
        elm_type_args += f'{tab}, '
        elm_type_args += f'{tab}, '.join([f'{p}: {pt}\n' for p,pt in elm_type_args_tuple[1:]])
    elm_type_args += tab + '}'

    all_elm_union_types_str = '\n\n'.join(all_elm_union_types)

    return f'''{all_elm_union_types_str}\n\ntype alias {elm_type_name} =\n{tab}{elm_type_args}\n'''.strip()



def generate_all_elm_types(schemas: dict[Any, Any]):
    print(colored('Assume every property is required', 'red'))
    print(colored('Assume pyton class name and elm type alias names are the same structure', 'red'))
    all_elm_type_alias = []  
    all_elm_encoder_fns = [] 
    for schema_name, schema_props in schemas.items():
        print(colored(f'{schema_name=}', 'yellow'))
        elm_type_name, elm_type_props_dict, all_elm_union_types, elm_encoder_fn, all_elm_union_encoders  = generate_elm_type_and_encoder_fn(schema_props)
        elm_type_alias = format_elm_types(elm_type_name, elm_type_props_dict, all_elm_union_types)
        all_elm_encoder_fns.append(format_elm_encoder_fn(elm_encoder_fn))
        for ute in all_elm_union_encoders:
                all_elm_encoder_fns.append(format_elm_encoder_fn(ute))

        print(colored(elm_type_alias, 'green'))
        print('-'*20)
        all_elm_type_alias.append(elm_type_alias)
    return all_elm_type_alias, all_elm_encoder_fns

if __name__ == "__main__":
    apis = get_openapi_config(local_openapi_json)
    elm_types, elm_encoder_fns = generate_all_elm_types(apis['components']['schemas'])
    route = '/api/db/question/{q_uuid}/record-query'
    method = 'put'

    fn_dict = generate_elm_api_function(route, method, apis['paths'][route][method])  
    print(colored(format_api_fn(fn_dict, method, ''), 'green'))
    '''
    write_http_fns_file(
            create_api_functions(apis), 
            elm_types=elm_types, elm_encoder_fns=elm_encoder_fns,  
            output_file="./codegen/src/ApiGen.elm",
            open_api_version=apis["openapi"],
            info=apis['info']
    )
    '''

