//! Input-only client: raw stream/rows/normal proxy scripts on stdin, actual
//! observations on stdout. It never opens a file or receives an expectation.
use std::cell::Cell;
use std::io::{self, BufRead};
use node94_format_request_protocol::{request, Context, Input, Requests, Row, Writer};

#[derive(Clone)]
enum Action { Method(u64), Row(usize, u64, u64), Context([u64; 5]), Write(Vec<u8>, bool) }
#[derive(Clone, Default)]
struct Script { reply: u8, actions: Vec<Action> }
enum Event {
    Write { method: u64, destination: u64, bytes: String, reply: u8 },
    Value { data: u64, second: u64, before: [u64; 5], after: [u64; 5], reply: u8 },
}
fn hex_word(s: &str) -> u64 { u64::from_str_radix(s, 16).expect("hex word") }
fn bytes(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "hex byte count");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex byte")).collect()
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|v| format!("{v:02x}")).collect() }
fn words(context: &Context) -> [u64; 5] {
    [context.destination, context.table, u64::from(context.options), u64::from(context.first), u64::from(context.second)]
}
fn array(a: &[u64]) -> String { format!("[{}]", a.iter().map(u64::to_string).collect::<Vec<_>>().join(",")) }
fn script(raw: &str) -> Vec<Script> {
    if raw == "-" { return Vec::new(); }
    raw.split(';').map(|entry| {
        let (reply, actions) = entry.split_once('~').expect("script separator");
        let actions = if actions.is_empty() { Vec::new() } else {
            actions.split('/').map(|action| {
                let (kind, argument) = action.split_at(1);
                match kind {
                    "M" => Action::Method(hex_word(argument)),
                    "R" => {
                        let v: Vec<_> = argument.split(',').map(hex_word).collect();
                        assert_eq!(v.len(), 3);
                        Action::Row(usize::try_from(v[0]).expect("row index"), v[1], v[2])
                    }
                    "C" => {
                        let v: Vec<_> = argument.split(',').map(hex_word).collect();
                        Action::Context(v.try_into().expect("five context words"))
                    }
                    "W" => {
                        let (data, propagate) = argument.rsplit_once(',').expect("nested flag");
                        assert!(propagate == "0" || propagate == "1");
                        Action::Write(bytes(data), propagate == "1")
                    }
                    _ => panic!("invalid supplied script operation"),
                }
            }).collect()
        };
        Script { reply: reply.parse().expect("u8 reply"), actions }
    }).collect()
}
struct Proxy<'a> {
    method: &'a Cell<u64>, rows: &'a [Row], table: u64,
    script: Vec<Script>, ordinal: usize, events: Vec<Event>,
}
impl Proxy<'_> {
    fn next(&mut self) -> Script {
        let result = self.script.get(self.ordinal).cloned().unwrap_or_default();
        self.ordinal += 1;
        result
    }
    fn apply(&mut self, script: Script, mut context: Option<&mut Context>) -> u8 {
        for action in script.actions {
            match action {
                Action::Method(method) => self.method.set(method),
                Action::Row(index, data, second) => {
                    let row = self.rows.get(index).expect("valid scripted row");
                    row.data.set(data); row.second.set(second);
                }
                Action::Context(v) => {
                    let c = context.as_deref_mut().expect("G context action");
                    *c = Context { destination: v[0], table: v[1],
                        options: u32::try_from(v[2]).expect("options u32"),
                        first: u16::try_from(v[3]).expect("first u16"),
                        second: u16::try_from(v[4]).expect("second u16") };
                }
                Action::Write(bytes, propagate) => {
                    let c = context.as_deref().expect("G nested write");
                    let method = if c.table == self.table { self.method.get() }
                        else { assert_eq!(c.table, 2, "known proxy table"); 202 };
                    let reply = self.write(method, c.destination, &bytes);
                    if propagate && reply != 0 { return reply; }
                }
            }
        }
        script.reply
    }
}
impl Requests for Proxy<'_> {
    fn write(&mut self, method: u64, destination: u64, data: &[u8]) -> u8 {
        let script = self.next();
        let index = self.events.len();
        self.events.push(Event::Write { method, destination, bytes: hex(data), reply: 0 });
        let reply = self.apply(script, None);
        if let Event::Write { reply: saved, .. } = &mut self.events[index] { *saved = reply; }
        reply
    }
    fn value(&mut self, data: u64, second: u64, context: &mut Context) -> u8 {
        let script = self.next();
        let index = self.events.len();
        let before = words(context);
        self.events.push(Event::Value { data, second, before, after: before, reply: 0 });
        let reply = self.apply(script, Some(context));
        if let Event::Value { after, reply: saved, .. } = &mut self.events[index] {
            *after = words(context); *saved = reply;
        }
        reply
    }
}
fn event_json(event: &Event) -> String {
    match event {
        Event::Write { method, destination, bytes, reply } => format!(
            "{{\"kind\":\"write\",\"method\":{method},\"destination\":{destination},\"bytes\":\"{bytes}\",\"return\":{reply}}}"),
        Event::Value { data, second, before, after, reply } => format!(
            "{{\"kind\":\"value\",\"data\":{data},\"second\":{second},\"before\":{},\"after\":{},\"return\":{reply}}}", array(before), array(after)),
    }
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("input line");
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 8, "eight input-only fields");
        let id = fields[0];
        assert!(id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        let raw = bytes(fields[2]);
        let destination = hex_word(fields[3]); let table = hex_word(fields[4]);
        let method = Cell::new(hex_word(fields[5]));
        let rows: Vec<_> = if fields[6] == "-" { Vec::new() } else {
            fields[6].split(',').map(|row| {
                let (first, second) = row.split_once(':').expect("paired row");
                Row::new(hex_word(first), hex_word(second))
            }).collect()
        };
        let mut proxy = Proxy { method: &method, rows: &rows, table,
            script: script(fields[7]), ordinal: 0, events: Vec::new() };
        let input = match fields[1] { "direct" => Input::Direct(&raw), "encoded" => Input::Encoded(&raw), _ => panic!("route") };
        let result = request(input, Writer { destination, table, method: &method }, &rows, &mut proxy);
        let status = match result { Ok(value) => value.to_string(), Err(_) => "\"refused\"".to_owned() };
        let events = proxy.events.iter().map(event_json).collect::<Vec<_>>().join(",");
        let rows = rows.iter().map(|r| format!("[{},{}]", r.data.get(), r.second.get())).collect::<Vec<_>>().join(",");
        println!("{{\"id\":\"{id}\",\"status\":{status},\"events\":[{events}],\"method\":{},\"rows\":[{rows}]}}", method.get());
    }
}
