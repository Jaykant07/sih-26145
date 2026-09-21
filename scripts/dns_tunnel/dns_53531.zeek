@load base/protocols/dns

event zeek_init()
    {
    Analyzer::register_for_port(Analyzer::ANALYZER_DNS, 53531/udp);
    }
