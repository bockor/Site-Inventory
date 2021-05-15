import json
import middleware.pyyed_143 as SIP
from middleware.nra_data import *
from configparser import ConfigParser
from collections import defaultdict
from datetime import datetime
import os
import shutil

def do_inventory(some_site):
    gateways = set()
    dnsz = set()
    windomains = set()
    connections = []
    netz_by_routing_dom = defaultdict(list)
    srvrz_by_routing_dom = defaultdict(list)

    #create objects
    selected_site = Site(some_site)

    with open (domaindb_file) as f:
        entries = json.load(f)
        for entry in entries:
            if entry['Site'] == some_site:
                n = Network(entry['Network'], entry['Classification'], entry['LanInfo'])
                if entry['RoutingDomain']:
                    netz_by_routing_dom[entry['RoutingDomain']].append(n)
                else:
                    netz_by_routing_dom["global"].append(n)
                if entry['Gateway']:
                    g = Gateway(entry['Gateway'],  entry['Site'],\
                        entry['Classification'])
                else:
                    #Assign a dummy GW if  "Gateway": null
                    g = Gateway('NO_GW',  entry['Site'])
                gateways.add(g)
                c = Connection(g, n)
                connections.append(c)

        # create DNS objects if the user checked "DNS"
                if areas_dnsz:
                    if entry['DNS']:
                        for dns in entry['DNS']:
                            d  = Dns(dns)
                            dnsz.add(d)
                            c = Connection(d, n, "short", "1.0", "dashed")
                            connections.append(c)

                # create WindowsDomain - ShortCommandID objects if the user checked "WindowsDomain"
                if areas_windomz :
                    #here's the famous WindowsDomain / ShortCmdId part
                    ##WindowsDomain / ShortCmdId are completed in current entry
                    w = None
                    if entry['Classification'] and entry['WindowsDomain'] and entry['ShortCmdId']:
                        w  = WindowsDomain(entry['WindowsDomain'],\
                               "{}{}".format(entry['Classification'], entry['ShortCmdId']))
                    ##ShortCmdId NOT completed in current entry    
                    elif entry['Classification'] and entry['WindowsDomain']:
                        for secdom, windom, scmd in ref_secdom_windom_scmd:
                            if entry['Classification'] == secdom and\
                                    entry['WindowsDomain'] == windom:
                                w  = WindowsDomain(entry['WindowsDomain'],\
                                    "{}{}".format(entry['Classification'], scmd)) 
                                break
                        # No match found in ref_secdom_windom_scmd
                        else:
                            w  = WindowsDomain(entry['WindowsDomain'], "NO_SCMDID")
                    ##WindowsDomain NOT completed in current entry  
                    elif entry['Classification'] and entry['ShortCmdId']:
                        for secdom, windom, scmd in ref_secdom_windom_scmd:
                            if entry['Classification'] == secdom and entry['ShortCmdId'] == scmd:
                                w  = WindowsDomain(windom,\
                                    "{}{}".format(entry['Classification'], entry['ShortCmdId'] ))
                                break
                        # No match found in ref_secdom_windom_scmd
                        else:
                            w  = WindowsDomain("NO_WINDOM",\
                                "{}{}".format(entry['Classification'], entry['ShortCmdId'] )) 

                    if w:
                        windomains.add(w)
                        c = Connection(w, n, "short", "1.0", "dashed")
                        connections.append(c)

    # create server objects if the user checked "Core Servers"
    if areas_servers:
        with open (servers_file) as f:
            entries = json.load(f)
            for entry in entries:
                for rd,netz in netz_by_routing_dom.items():
                    for net in netz:
                        if net.ip_in_network(entry['ipv4addr']):
                            if(DEBUG):
                                print ("[SERVER_FOUND] ", entry['ipv4addr'], '-->', net.get_label())
                            s = Server(entry['ServerName'],\
                                entry['ipv4addr'],\
                                net.get_color(),\
                                os = entry['OperationSystem'],\
                                server_type=entry['ServerType'])
                            srvrz_by_routing_dom[rd].append(s)
                            c = Connection(s, net, "none", "1.0", "line")
                            connections.append(c)
                            break


    #create graph
    g = SIP.Graph()
    #create graphml file name
    graphml_filename = '{}.graphml'.format(selected_site.get_label())
    #define node custom properties (for server objects)
    g.define_custom_property("node", "ipv4addr", "string", "")
    g.define_custom_property("node", "os", "string", "")
    g.define_custom_property("node", "server_type", "string", "")

    ##yEd site group
    site_group = g.add_group(selected_site.get_label(),\
        shape=Site.get_shape(),\
        font_size=Site.get_font_size(),\
        fill=Site.get_fill())

    ##yEd nodes
    ###yEd network nodes
    for rd,netz in dict(netz_by_routing_dom).items():
        if rd == "global":
            for net in netz:
                site_group.add_node(net.get_label(),\
                    shape_fill=net.get_color(),\
                    shape=Network.get_shape(),\
                    height=Network.get_height(),\
                    width=Network.get_width())

            ###yEd Server Nodes
            ### Only when the user checked "Core Servers"
            if areas_servers:
                for rd2,srvrz in dict(srvrz_by_routing_dom).items():
                    if rd2 == "global":
                        for srv in srvrz:
                            site_group.add_node(srv.get_label(),\
                                shape_fill=srv.get_color(),\
                                shape=Server.get_shape(),\
                                height=Server.get_height(),\
                                width=Server.get_width(),\
                                custom_properties={"ipv4addr": srv.get_ipv4addr(),\
                                      "os": srv.get_os(),\
                                      "server_type": srv.get_server_type()}\
                            )
        else:
            rd_group = site_group.add_group(rd,\
                shape=RoutingDomain.get_shape(),\
                font_size=RoutingDomain.get_font_size(),\
                fill=RoutingDomain.get_fill())
            for net in netz:
                rd_group.add_node(net.get_label(),\
                    shape_fill=net.get_color(),\
                    shape=Network.get_shape(),\
                    height=Network.get_height(),\
                    width=Network.get_width())

            ###yEd Server Nodes
            ### Only when the user checked "Core Servers"
            if areas_servers:
                for rd2,srvrz in dict(srvrz_by_routing_dom).items():
                    if rd == rd2:
                        for srv in srvrz:                  
                            rd_group.add_node(srv.get_label(),\
                                shape_fill=srv.get_color(),\
                                shape=Server.get_shape(),\
                                height=Server.get_height(),\
                                width=Server.get_width(),\
                                custom_properties={"ipv4addr": srv.get_ipv4addr(),\
                                       "os": srv.get_os(),\
                                       "server_type": srv.get_server_type()}\
                            )

    #yEd dns nodes
    ### Only when the user checked "DNS"
    if areas_dnsz:
        for dns in list(dnsz):
            site_group.add_node(dns.get_label(),\
                shape_fill=Dns.get_color(),\
                shape=Dns.get_shape(),\
                height=Dns.get_height(),\
                width=Dns.get_width())

    ###yEd WindowsDomain nodes
    ### Only when the user checked "WindowsDomain"
    if areas_windomz :
        for win in list(windomains):
            site_group.add_node(win.get_label(),\
                shape_fill=WindowsDomain.get_color(),\
                shape=WindowsDomain.get_shape(),\
                height=WindowsDomain.get_height(),\
                width=WindowsDomain.get_width())

    ###yEd Gateway nodes
    for gw in list(gateways):
        site_group.add_node(gw.get_label(),\
            shape_fill=gw.get_color(),\
            shape=Gateway.get_shape(),\
            height=Gateway.get_height(),\
            width=Gateway.get_width(),\
            url=gw.get_f8_url())

    #yEd edges
    for conn in connections:
        if isinstance(conn.get_src_node(), Gateway):
            ##yEd gateway -> network edge
            g.add_edge(conn.get_src_node().get_label(),\
                conn.get_dst_node().get_label(),\
                arrowhead=conn.get_arrowhead(),\
                width=conn.get_width(),\
                color=conn.get_color(),\
                label = conn.get_dst_node().get_lan_info())
        else:
            g.add_edge(conn.get_src_node().get_label(),\
                conn.get_dst_node().get_label(),\
                width=conn.get_width(),\
                color=conn.get_color(),\
                arrowhead=conn.get_arrowhead(),\
                line_type=conn.get_line_type())

    # write graph to file
    g.write_graph("{}/{}.graphml".format(bulk_folder, some_site), pretty_print=True)
    print ("writing YED-GRAPHML file for: {}".format(some_site))


if __name__ == '__main__':
    #Read Config File
    parser = ConfigParser()
    parser.read('config_bulk.ini')
    DEBUG = parser.getboolean('DEFAULT', 'DEBUG')
    domaindb_file = parser.get('DEFAULT', 'domaindb_file')
    servers_file = parser.get('DEFAULT', 'servers_file')
    areas_windomz = parser.getboolean('DEFAULT', 'areas_windomz')
    areas_dnsz = parser.getboolean('DEFAULT', 'areas_dnsz')
    areas_servers = parser.getboolean('DEFAULT', 'areas_servers')
    compress_bulk_folder = parser.getboolean('DEFAULT', 'compress_bulk_folder')

    #Build reference to alleviate missing WindowsDomain's and ShortCmdId's ...
    ref_secdom_windom_scmd = set()
    # ... and get unique Site Names
    site_names_frm_json = set()

    with open (domaindb_file) as f:
        entries = json.load(f)
        for entry in entries:
            if entry['Classification'] and entry['WindowsDomain'] and entry['ShortCmdId']:
                ref_secdom_windom_scmd.add((entry['Classification'] ,\
                        entry['WindowsDomain'] , entry['ShortCmdId'] ))
            site_names_frm_json.add(entry['Site'])

    #Generate folder name ...
    bulk_folder = 'bulk_{}'.format(datetime.now().strftime("%d%m%Y"))
    # ... and create the folder
    try:
        os.makedirs(bulk_folder)
    except:
        #catch FileExistsError here
        pass

    for site in site_names_frm_json:
        do_inventory(site)

    #Compress the folder
    if compress_bulk_folder:
        shutil.make_archive(bulk_folder, 'zip', bulk_folder)
