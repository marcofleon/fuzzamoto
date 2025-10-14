// Simple test to demonstrate CreateConnection functionality
use fuzzamoto_ir::{
    ProgramBuilder, ProgramContext, CreateConnectionGenerator, Generator,
};
use rand::thread_rng;

fn main() {
    // Create a program context with 1 node and 8 existing connections
    let context = ProgramContext {
        num_nodes: 1,
        num_connections: 8,
        timestamp: 1234567890,
    };

    // Create a program builder
    let mut builder = ProgramBuilder::new(context);
    let mut rng = thread_rng();

    // Use the CreateConnection generator
    let generator = CreateConnectionGenerator;
    
    println!("Generating a program with CreateConnection operation...");
    
    match generator.generate(&mut builder, &mut rng) {
        Ok(_) => {
            println!("✓ Successfully generated CreateConnection instructions");
            
            // Finalize the program
            match builder.finalize() {
                Ok(program) => {
                    println!("✓ Program is valid with {} instructions", program.instructions.len());
                    
                    // Print the instructions
                    println!("\nGenerated IR program:");
                    for (i, instr) in program.instructions.iter().enumerate() {
                        println!("  {}: {:?}", i, instr.operation);
                    }
                    
                    // Compile the program
                    use fuzzamoto_ir::compiler::{Compiler, CompiledAction};
                    let mut compiler = Compiler::new();
                    
                    match compiler.compile(&program) {
                        Ok(compiled) => {
                            println!("\n✓ Program compiled successfully");
                            println!("\nCompiled actions:");
                            for (i, action) in compiled.actions.iter().enumerate() {
                                match action {
                                    CompiledAction::Connect(node, conn_type) => {
                                        println!("  {}: Connect to node {} with type '{}'", i, node, conn_type);
                                    }
                                    CompiledAction::SendRawMessage(conn, msg, _) => {
                                        println!("  {}: SendRawMessage on connection {} type '{}'", i, conn, msg);
                                    }
                                    CompiledAction::SetTime(time) => {
                                        println!("  {}: SetTime to {}", i, time);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("✗ Compilation failed: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("✗ Program finalization failed: {:?}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("✗ Generation failed: {:?}", e);
        }
    }
}

