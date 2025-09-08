fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("schema")
        .file("schema/common.capnp")
        .file("schema/echo.capnp")
        .file("schema/init.capnp")
        .file("schema/mining.capnp")
        .file("schema/proxy.capnp")
        .run()
        .expect("compiling schema");
}
