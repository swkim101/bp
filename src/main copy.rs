use clap::Parser;
use elf::ElfBytes;
use elf::endian::AnyEndian;

#[repr(C, packed)]
struct Patch {
    addr: u64,
    data: Vec<u8>,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value_t = 0)]
    count: i32,
    
    name: String,
}

fn main() {
    let args = Args::parse();
    let path = std::path::PathBuf::from(&args.name);
    let file_data = std::fs::read(path).expect("Could not read file.");
    println!("{:?}", args);
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

    file.section_headers().expect("Get section headers").iter().for_each(|sh| {
        println!("Section: {:?}", sh);
    });

    {
        let shstrtab = file.section_header_by_name(".shstrtab")
            .expect("section table should be parseable")
            .expect("file should have a .shstrtab section");
        println!("{:?}", shstrtab);
        let shstrtab_data = &file_data[(shstrtab.sh_offset as usize)..];
        let s = shstrtab.sh_name as usize;
        let len = (&shstrtab_data[s..]).iter().position(|&x| x == 0).expect("string should end with 0");
        let aa = &shstrtab_data[s..(s+len)];
        println!("{:?}", std::str::from_utf8(aa).expect("cannot convert to utf8"));
        // aa.split(|x| *x == 0).enumerate().for_each(|(_size, content)| {
        //     println!("{:?}", std::str::from_utf8(content).expect("cannot convert to utf8"));
        // });
    }

    let f = std::path::PathBuf::from("./test.bin");
    let mut c = file_data.clone();
    c[0] = 0;
    std::fs::write(f, c).expect("Cannot write test.bin");

    
    println!("Hello, world!");
}
