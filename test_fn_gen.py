from get_all_routes import add_url_parameters_to_fn, format_api_fn


def test_fn_definition_outputs_correct_string_output():
    elm_fn_definition_dict = {
        "fn_name": "mode_api_mode_get",
        "args": ["(WebData a -> msg)", "D.Decoder a"],
        "args_names": ["msg", "decoder"],
        "output_arg": "Cmd msg",
        "fn_body": {
            "route": '"/api/mode"',
            "http_method": "get",
            "http_builder_fns": [
                "        |> HttpBuilder.withTimeout 90000",
                "        |> HttpBuilder.withExpect\n            (Http.expectJson (RemoteData.fromResult >> msg) decoder)",
                "        |> HttpBuilder.request",
            ],
        },
    }
    elm_fn_str = """
mode_api_mode_get : (WebData a -> msg) -> D.Decoder a -> Cmd msg
mode_api_mode_get msg decoder =
    "/api/mode"
        |> HttpBuilder.get
        |> HttpBuilder.withTimeout 90000
        |> HttpBuilder.withExpect
            (Http.expectJson (RemoteData.fromResult >> msg) decoder)
        |> HttpBuilder.request
    """.strip()
    formatted_fn_output = format_api_fn(
        elm_fn_definition_dict,
        # elm_fn_definition,
        # elm_fn_arguments,
        # route,
        "get",
        "",
    )
    print(formatted_fn_output)
    print(elm_fn_str)
    assert formatted_fn_output == elm_fn_str


def test_fn_url_param_output():
    elm_route, args, args_names = add_url_parameters_to_fn(
        {
            "parameters": [
                {
                    "name": "uuid",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "title": "Uuid"},
                }
            ]
        },
        args=[],
        args_names=[],
        elm_route='"' + "/api/db/question/{uuid}" + '"',
        route="/api/db/question/{uuid}",
    )
    assert len(args) == 1
    assert args[0] == "String"
    assert elm_route == '"/api/db/question/"++ uuid'
