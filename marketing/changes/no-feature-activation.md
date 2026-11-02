### An activation without brevo compiles

`MarketingQuery` and `MarketingMutation` are tagged `plugin_feature_svc = "brevo"`, like every rpc in them and every table they read or write. Without the feature, the feature filter dropped `types/models.proto` but kept the two service files, each now holding an empty service and an import of the dropped file, so no activation without `brevo` compiled (`open …/types/models.proto: no such file`). Both files now drop with the models.
