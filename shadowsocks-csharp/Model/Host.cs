using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using Shadowsocks.Controller;

namespace Shadowsocks.Model
{
    class HostNode
    {
        public bool include_sub;
        public string addr;
        public string rule;
        public int order;
        public Dictionary<string, HostNode> subnode;

        public HostNode()
        {
            include_sub = false;
            addr = "";
            rule = "";
            order = -1;
            subnode = new Dictionary<string, HostNode>();
        }

        public HostNode(bool sub, string addr, string rule, int order)
        {
            include_sub = sub;
            this.addr = addr;
            this.rule = rule;
            this.order = order;
            subnode = null;
        }
    }

    public class HostMap
    {
        Dictionary<string, HostNode> root = new Dictionary<string, HostNode>();
        IPSegment ips = new IPSegment("remoteproxy");
        int ruleOrder = 0;

        static HostMap instance = new HostMap();
        const string HOST_FILENAME = "user.rule";

        public static HostMap Instance()
        {
            return instance;
        }

        public void Clear(HostMap newInstance)
        {
            if (newInstance == null)
            {
                instance = new HostMap();
            }
            else
            {
                instance = newInstance;
            }
        }

        public void AddHost(string host, string addr)
        {
            IPAddress ip_addr = null;
            if (IPAddress.TryParse(host, out ip_addr))
            {
                string[] addr_parts = addr.Split(new char[] { ' ', '\t', }, 2, StringSplitOptions.RemoveEmptyEntries);
                if (addr_parts.Length >= 2)
                {
                    ips.insert(new IPAddressCmp(host), new IPAddressCmp(addr_parts[0]), addr_parts[1]);
                    return;
                }
            }

            string[] parts = host.Split('.');
            Dictionary<string, HostNode> node = root;
            bool include_sub = false;
            int end = 0;
            if (parts[0].Length == 0)
            {
                end = 1;
                include_sub = true;
            }

            int order = ++ruleOrder;

            for (int i = parts.Length - 1; i > end; --i)
            {
                if (!node.ContainsKey(parts[i]))
                {
                    node[parts[i]] = new HostNode();
                }
                if (node[parts[i]].subnode == null)
                {
                    node[parts[i]].subnode = new Dictionary<string, HostNode>();
                }
                node = node[parts[i]].subnode;
            }

            node[parts[end]] = new HostNode(include_sub, addr, host, order);
        }

        public bool GetHost(string host, out string addr)
        {
            string[] parts = host.Split('.');
            Dictionary<string, HostNode> node = root;
            HostNode bestNode = null;
            int bestOrder = -1;
            addr = null;

            for (int i = parts.Length - 1; i >= 0; --i)
            {
                if (!node.ContainsKey(parts[i]))
                    break;

                HostNode current = node[parts[i]];

                if (current.addr.Length > 0 &&
                    (current.include_sub || i == 0) &&
                    current.order > bestOrder)
                {
                    bestNode = current;
                    bestOrder = current.order;
                }

                if (i > 0 && current.subnode != null &&
                    current.subnode.ContainsKey("*"))
                {
                    HostNode wildcard = current.subnode["*"];
                    if (wildcard.addr.Length > 0 &&
                        wildcard.order > bestOrder)
                    {
                        bestNode = wildcard;
                        bestOrder = wildcard.order;
                    }
                }

                if (current.subnode == null)
                    break;

                node = current.subnode;
            }

            if (bestNode != null)
            {
                addr = bestNode.addr;

                Logging.Info("[HostMap] host=" + host
                    + " matched=" + bestNode.rule
                    + " order=" + bestNode.order
                    + " addr=" + addr);
                return true;
            }

            return false;
        }

        public bool GetIP(IPAddress ip, out string addr)
        {
            string host = ip.ToString();
            addr = ips.Get(new IPAddressCmp(host)) as string;
            return addr != null;
        }

        public bool LoadHostFile()
        {
            string filename = HOST_FILENAME;
            string absFilePath = System.IO.Path.Combine(System.Windows.Forms.Application.StartupPath, filename);
            if (System.IO.File.Exists(absFilePath))
            {
                try
                {
                    using (System.IO.StreamReader stream = System.IO.File.OpenText(absFilePath))
                    {
                        while (true)
                        {
                            string line = stream.ReadLine();
                            if (line == null)
                                break;
                            if (line.Length > 0 && line.StartsWith("#"))
                                continue;
                            string[] parts = line.Split(new char[] { ' ', '\t', }, 2, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length < 2)
                                continue;
                            AddHost(parts[0], parts[1]);
                        }
                    }
                    return true;
                }
                catch
                {
                    return false;
                }
            }
            return false;
        }
    }
}
