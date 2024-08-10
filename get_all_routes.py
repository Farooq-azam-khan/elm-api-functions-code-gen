import requests
from termcolor import colored, cprint

resp = requests.get('http://localhost:8000/openapi.json')
apis = resp.json()
elm_functions = [] 

skip_non_api_routes = True 

def create_api_functions(apis):
    for route, methods in apis['paths'].items():
        if skip_non_api_routes and not route.startswith('/api'): 
            print('skipping:', route)
            continue 
        print('-'*25)
        print('route:', route)

        for method, method_vals in methods.items():
            print('keys=', method_vals.keys())
            elm_function_name = method_vals["operationId"]
            elm_fn_definition_dict = {
                'fn_name': elm_function_name, 
                'args': ['(WebData a -> msg)', 'D.Decoder a'], 
                'args_names': ['msg', 'decoder'], 
                'output_arg': 'Cmd msg'
            }
            elm_request_encoder = ""
            if 'requestBody' in method_vals:
                elm_fn_definition_dict['args'].insert(0, 'E.Value')
                elm_fn_definition_dict['args_names'].insert(0, 'request_body_encoder')
                elm_request_encoder = "\n        |> HttpBuilder.withJsonBody request_body_encoder"
                # TODO: create encoder based on apis['components']['schemas']
            
            elm_route = '"' + route + '"'
            if 'parameters' in method_vals:
                parameters = method_vals['parameters']
                route_path = route.split('/')
                print(f'\tparameters (total={len(parameters)}):', parameters)
                for rp in route_path:
                    if '{' in rp and '}' in rp:
                        for url_param in parameters:
                            if url_param['in'] == 'path':
                                if rp.replace('{', '').replace('}', '') == url_param['name']:
                                    elm_route = elm_route.replace(rp, f"\"++ {url_param['name']} ++\"")
                                    elm_fn_definition_dict['args'].insert(0, 'String')
                                    elm_fn_definition_dict['args_names'].insert(0, url_param['name'])
                elm_route = elm_route.replace('++""', '')

            elm_fn_definition = f'{elm_fn_definition_dict["fn_name"]} : {" -> ".join(elm_fn_definition_dict["args"])} -> {elm_fn_definition_dict["output_arg"]}'
            elm_fn_arguments = f'{elm_fn_definition_dict["fn_name"]} {" ".join(elm_fn_definition_dict["args_names"])} ='
            
            formatted_fn_output = f'''
{elm_fn_definition}
{elm_fn_arguments}
    {elm_route}
    |> HttpBuilder.{method}{elm_request_encoder}
    |> HttpBuilder.withTimeout 90000
    |> HttpBuilder.withExpect
        (Http.expectJson (RemoteData.fromResult >> msg) decoder)
    |> HttpBuilder.request
'''.strip()
            
            if 'requestBody' in method_vals: 
                print('requestBody=', method_vals['requestBody'])
            if 'responses' in method_vals: 
                happy_path = method_vals['responses']['200']
                print('\tresponses=')
                happy_path_response_schema = happy_path['content']['application/json']['schema']
                print('\t', f'200 schemas={len(happy_path_response_schema.keys())}', happy_path)
                if len(happy_path_response_schema.keys()) == 0:
                    print(colored('HELP: define response schema', 'yellow'))

                # TODO: consider non happy path 
                # for resp_key, resp_val in method_vals['responses'].items(): 
                #     print('\t', resp_key, resp_val)
            
            
            print(colored(formatted_fn_output, 'green'))
            elm_functions.append(formatted_fn_output)
    return elm_functions

python_type_to_elm_encoder_type = {
    'string': 'E.string', 
    'array': 'E.list TODO:ref_encoder',
    'boolean': 'E.bool', 
    'integer': 'E.int',
    'number': 'E.float'
}
def write_encoders(apis):
    encoder_fns = []
    for tpe, tpe_props in apis['components']['schemas'].items():
        if tpe_props['type'] == 'object':
            elm_properties = []
            print('-'*25)
            print(colored(tpe, 'red'))
            print(f'{tpe_props.keys()=}')
            if 'required' in tpe_props:
                print(f'required={tpe_props["required"]}')
            print(f'title={tpe_props["title"]}')
            print('properties:', tpe_props['properties'])
            for prop_name, prop_type in tpe_props['properties'].items():
                if 'type' in prop_type:
                    python_type = prop_type['type']
                    if python_type == 'array': 
                        if 'items' in prop_type:
                            print(colored(prop_type['items'], 'yellow'))
                    else: 
                        encoder_type = python_type
                        if python_type not in python_type_to_elm_encoder_type:
                            print(colored(f'{python_type} not in python_type_to_elm_encoder_type', 'red'))
                        else:
                            encoder_type = python_type_to_elm_encoder_type[python_type]
                        elm_prop_tupe_str = f'("{prop_name}", {encoder_type} TODO:VAR)'
                else: 
                    
                    elm_prop_tupe_str = f'("{prop_name}", {encoder_type} TODO:ref_encoder)'
                    
                elm_properties.append(elm_prop_tupe_str)
            elm_schema_encoder_str = f''' 
dummy_encoder : E.Value
dummy_encoder = E.object [{", ".join(elm_properties)}]
'''.strip()
            print(colored(elm_schema_encoder_str, 'green'))
    return encoder_fns

'''
(E.object [ ( "query", E.string query ) ]
{'properties': {'query': {'type': 'string', 'title': 'Query'}}, 'type': 'object', 'required': ['query'], 'title': 'DBQuery'}
class DBQuery(BaseModel):
    query: str
'''

def write_file(output_file='./codegen/ApiGen.elm'):
    print(colored('writing file', 'green'))
    elm_functions = create_api_functions(apis)
    print(colored(f'writing {len(elm_functions)} api functions', 'green'))
    functions_str = '\n\n'.join(elm_functions)
    file_content = f'''
module ApiGen exposing(..)

import Http
import HttpBuilder
import Json.Decode as D
import Json.Encode as E
import RemoteData exposing (RemoteData(..), WebData)

{functions_str}
    '''.strip()

    with open(output_file, 'w') as f: 

        f.write(file_content)

if __name__ == '__main__': 
    
    #write_file()
    write_encoders(apis)