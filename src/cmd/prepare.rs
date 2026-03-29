use clap::builder::Str;
use std::process::{Command, Stdio};
use std::fs;
use std::path::PathBuf;

struct Preparer {
    cc: String,
    files: Vec<String>,
    workdir: String,
    output: String,
}

struct Compiler {
    cc: String,
    workdir: String,
}

impl Compiler {
    pub fn new(cc: String, workdir: String) -> Result<Self, String> {
        Command::new(&cc)
            .arg("--version")
            .output()
            .map_err(|_| format!("compiler not found: {}", cc))?;

        fs::create_dir_all(&workdir).map_err(|e| format!("failed to create workdir: {}", e))?;

        Ok(Self { cc, workdir })
    }

    pub fn compile(&self, source: &str) -> Result<Vec<u8>, String> {
        let out_path = PathBuf::from(&self.workdir).join("temp.o");
        let out = Command::new(&self.cc)
            .args(["-static", "-c", source, "-o", out_path.to_str().unwrap()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("spawn failed: {}", e))?;

        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).to_string());
        }

        Ok(out.stdout)
    }
}


impl Preparer {
    fn prepare(&self) -> Result<i32, String> {
        let compiler = Compiler::new(self.cc.clone(), self.workdir.clone())?;
        compiler.compile(self.files[0].clone().as_str())?;
        Ok(0)
    }
}

pub fn run(cc: String, file: Vec<String>) {
    let p = Preparer {
        cc: cc,
        files: file,
        workdir: ".bp".to_string(),
        output: "patch.bp".to_string(),
    };

    p.prepare().expect("prepare error:");
}
