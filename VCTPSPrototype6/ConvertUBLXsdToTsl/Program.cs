using System;
using System.Data;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Xml;
using System.IO;
using System.Reflection;
using System.Text;
using System.Collections.Generic;
using System.Diagnostics;

namespace OberonExample1
{
    public class Program
    {
        static async Task Main(string[] args)
        {
            string namedOrder = "Order";
            string namedOrderType = "OrderType";
            string namedWaybill = "Waybill";
            string namedWaybillType = "WaybillType";
            string namedTransportationStatus = "TransportationStatus";
            string namedTransportationStatusType = "TransportationStatusType";
            string namedInvoice = "Invoice";
            string namedInvoiceType = "InvoiceType";

            string[] namedtypes = new string[] { "Order", "Waybill", "TransportationStatus", "Invoice" };
            namedtypes = new string[] { "Invoice" };
            string[] extranamedtypes = new string[] { "Item", "Party", "Location" };
            extranamedtypes = new string[] { };

            string[] xsdUrls = new string[] { 
                "http://docs.oasis-open.org/ubl/os-UBL-2.1/xsdrt/common/UBL-CommonAggregateComponents-2.1.xsd",
                "http://docs.oasis-open.org/ubl/os-UBL-2.2/xsdrt/maindoc/UBL-Order-2.2.xsd",
                "http://docs.oasis-open.org/ubl/os-UBL-2.2/xsdrt/maindoc/UBL-Waybill-2.2.xsd",
                "http://docs.oasis-open.org/ubl/os-UBL-2.2/xsdrt/maindoc/UBL-TransportationStatus-2.2.xsd",
                "http://docs.oasis-open.org/ubl/os-UBL-2.2/xsdrt/maindoc/UBL-Invoice-2.2.xsd"
            };

            //HttpClient httpClient = new HttpClient();
            //HttpResponseMessage response = await httpClient.GetAsync(xsdUrl);
            //response.EnsureSuccessStatusCode();
            //string responseBody = await response.Content.ReadAsStringAsync();

            // Phase 1 - Build the type database
            Dictionary<string,string> nametypes1 = new Dictionary<string,string>();
            Dictionary<string,string> typepropertytypes1 = new Dictionary<string,string>(); 

            string structname = "";

            foreach (string url in xsdUrls)
            {
                XmlTextReader xmlTextReader = new XmlTextReader(url);
                while (xmlTextReader.Read())
                {
                    //Console.WriteLine(xmlTextReader.Name);
                    if (xmlTextReader.Name == "xsd:complexType")
                    {
                        structname = xmlTextReader.GetAttribute("name");
                    }
                    else if (xmlTextReader.Name == "xsd:element")
                    {
                        string attrname = xmlTextReader.GetAttribute("name");
                        string attrtype = xmlTextReader.GetAttribute("type");
                        if (!String.IsNullOrEmpty(attrname) && !String.IsNullOrEmpty(attrtype))
                        {
                            nametypes1.Add(attrname, attrtype);
                        }
                        else
                        {
                            string attrref = xmlTextReader.GetAttribute("ref");
                            if (!String.IsNullOrEmpty(attrref))
                            {
                                if (!attrref.StartsWith("ext:"))
                                {
                                    string propertytype = "";
                                    string attref2 = attrref.Replace("cac:", "").Replace("cbc:", "");
                                    string attrtype2;
                                    if (attrref.StartsWith("cbc:"))
                                        attrtype2 = "string";
                                    else
                                        attrtype2 = "Cac_" + nametypes1[attref2].Replace("Type", "");
                                    if (attrtype2.EndsWith("Party") || attrtype2.EndsWith("Location")
                                        || attrtype2.EndsWith("PriceList") || attrtype2.EndsWith("CreditNoteLine")
                                        || attrtype2.EndsWith("DebitNoteLine") || attrtype2.EndsWith("InvoiceLine")
                                        || attrtype2.EndsWith("LineItem") || attrtype2.EndsWith("RequestForTenderLine")
                                        || attrtype2.EndsWith("AwardingCriterion") || attrtype2.EndsWith("AwardingCriterionResponse")
                                        || attrtype2.EndsWith("ClassificationCategory") || attrtype2.EndsWith("Consignment")
                                        || attrtype2.EndsWith("GoodsItem") || attrtype2.EndsWith("Package")
                                        || attrtype2.EndsWith("TenderLine") || attrtype2.EndsWith("TransportEquipment")
                                        || attrtype2.EndsWith("Shipment") || attrtype2.EndsWith("TransportEvent")
                                        || attrtype2.EndsWith("ProcurementProjectLot")
                                    )
                                    {
                                        attrtype2 = "string";
                                        attrref += "Udid";
                                    }
                                    propertytype = attrtype2;
                                    if (typepropertytypes1.ContainsKey(structname))
                                    {
                                        if (!typepropertytypes1[structname].Contains("\"" + propertytype + "\""))
                                        {
                                            typepropertytypes1[structname] += "," + "\"" + propertytype + "\"";
                                        }
                                    }
                                    else
                                    {
                                        typepropertytypes1.Add(structname, "\"" + propertytype + "\"");
                                    }
                                    //if (structname.Contains("CreditNoteLine")) Debugger.Break();
                                    if (("Cac_" + structname).Replace("Type", "") == attrtype2)
                                    {
                                        Console.WriteLine(attrtype2);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Console.WriteLine("typepropertytypes.Keys.Count: " + typepropertytypes1.Keys.Count.ToString() + " total types");

            string prefix = "Cac_";
            string postfix = "";
            Console.Write("struct " + prefix + namedOrder + postfix + "\n{\n");
            Console.WriteLine(typepropertytypes1[namedOrderType]);
            Console.WriteLine("}\n");
            Console.Write("struct " + prefix + namedWaybill + postfix + "\n{\n");
            Console.WriteLine(typepropertytypes1[namedWaybillType]);
            Console.WriteLine("}\n");
            Console.Write("struct " + prefix + namedTransportationStatus + postfix + "\n{\n");
            Console.WriteLine(typepropertytypes1[namedTransportationStatusType]);
            Console.WriteLine("}\n");
            Console.Write("struct " + prefix + namedInvoice + postfix + "\n{\n");
            Console.WriteLine(typepropertytypes1[namedInvoiceType]);
            Console.WriteLine("}\n");

            UniqueTypes.Clear();
            foreach(string namedtype in namedtypes)
            {
                UniqueTypes.Add("Cac_" + namedtype, -1);
                Console.WriteLine("Cac_" + namedtype + "\t" + "-1");
                ProcessPropertyType(typepropertytypes1, namedtype + "Type", 0);
            }
            Console.WriteLine("typepropertytypes.Keys.Count: " + UniqueTypes.Keys.Count.ToString() + " unique types");

            // Phase 2 - Build the type output definitions
            SortedDictionary<string, string> nametypes2 = new SortedDictionary<string, string>();
            Dictionary<string, string> typeproperties2 = new Dictionary<string, string>();
            foreach (string url in xsdUrls)
            {
                XmlTextReader xmlTextReader = new XmlTextReader(url);
                while (xmlTextReader.Read())
                {
                    //Console.WriteLine(xmlTextReader.Name);
                    if (xmlTextReader.Name == "xsd:complexType")
                    {
                        structname = xmlTextReader.GetAttribute("name");
                    }
                    else if (xmlTextReader.Name == "xsd:element")
                    {
                        string attrname = xmlTextReader.GetAttribute("name");
                        string attrtype = xmlTextReader.GetAttribute("type");
                        if (!String.IsNullOrEmpty(attrname) && !String.IsNullOrEmpty(attrtype))
                        {
                            nametypes2.Add(attrname, attrtype);
                        }
                        else
                        {
                            string attrref = xmlTextReader.GetAttribute("ref");
                            if (!String.IsNullOrEmpty(attrref))
                            {
                                if (!attrref.StartsWith("ext:"))
                                {
                                    string property = "";
                                    string attref2 = attrref.Replace("cac:", "").Replace("cbc:", "");
                                    string attrtype2;
                                    string comment = "";
                                    string minOccurs = xmlTextReader.GetAttribute("minOccurs");
                                    string optionalattr = "";
                                    if (minOccurs == "0")
                                    {
                                        optionalattr = "optional ";
                                    }
                                    if (attrref.EndsWith("Date") || attrref.EndsWith("Time"))
                                    {
                                        attrtype2 = "DateTime";
                                    }
                                    else if (attrref.StartsWith("cbc:"))
                                        attrtype2 = "string";
                                    else
                                        attrtype2 = "Cac_" + nametypes2[attref2].Replace("Type", "");
                                    if (attrtype2.EndsWith("Party") || attrtype2.EndsWith("Location")
                                        || attrtype2.EndsWith("PriceList") || attrtype2.EndsWith("CreditNoteLine")
                                        || attrtype2.EndsWith("DebitNoteLine") || attrtype2.EndsWith("InvoiceLine")
                                        || attrtype2.EndsWith("LineItem") || attrtype2.EndsWith("RequestForTenderLine")
                                        || attrtype2.EndsWith("AwardingCriterion") || attrtype2.EndsWith("AwardingCriterionResponse")
                                        || attrtype2.EndsWith("ClassificationCategory") || attrtype2.EndsWith("Consignment")
                                        || attrtype2.EndsWith("GoodsItem") || attrtype2.EndsWith("Package")
                                        || attrtype2.EndsWith("TenderLine") || attrtype2.EndsWith("TransportEquipment")
                                        || attrtype2.EndsWith("Shipment") || attrtype2.EndsWith("TransportEvent")
                                        || attrtype2.EndsWith("ProcurementProjectLot")
                                        )
                                    {
                                        comment = " // " + optionalattr + attrtype2;
                                        attrtype2 = "string";
                                        attrref += "Udid";
                                    }
                                    string maxOccurs = xmlTextReader.GetAttribute("maxOccurs");
                                    if (!String.IsNullOrEmpty(maxOccurs) && maxOccurs == "unbounded")
                                    {
                                        property = "\n\t" + optionalattr + "List<" + attrtype2 + ">\t" + attrref.Replace(":", "_") + ";" + comment;
                                    }
                                    else
                                    {
                                        property = "\n\t" + optionalattr + attrtype2 + "\t" + attrref.Replace(":", "_") + ";" + comment;
                                    }
                                    if (typeproperties2.ContainsKey(structname))
                                    {
                                        typeproperties2[structname] += property;
                                    }
                                    else
                                    {
                                        typeproperties2.Add(structname, property);
                                    }
                                    //if (structname.Contains("CreditNoteLine")) Debugger.Break();
                                    if (("Cac_" + structname).Replace("Type", "") == attrtype2)
                                    {
                                        Console.WriteLine(attrtype2);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            StreamWriter file1 = new StreamWriter("c:\\temp\\subtypes.ts");

            prefix = "Cac_";
            postfix = "";
            int ntypes = 0;
            foreach (string name in nametypes2.Keys)
            {
                //if (name != name2)
                {
                    if (UniqueTypes.Keys.Contains("Cac_" + name))
                    {
                        string type = nametypes2[name];
                        file1.Write("struct " + prefix + name + postfix + "\n{");
                        file1.WriteLine(typeproperties2[type]);
                        file1.WriteLine("}\n");
                        ntypes++;
                    }
                }
            }
            file1.Close();
            Console.WriteLine("No. types output: " + ntypes.ToString());

            Assembly assembly = Assembly.GetExecutingAssembly();
            var streams = assembly.GetManifestResourceNames();

            foreach (string typename in namedtypes.Concat<string>(extranamedtypes))
            {
                StreamWriter file2 = new StreamWriter("c:\\temp\\" + typename + ".ts");

                var jsonStream = assembly.GetManifestResourceStream("ConvertUBLXsdToTsl.ubltsltemplate.txt");
                byte[] res = new byte[jsonStream.Length];
                int nBytes = jsonStream.Read(res);
                string template = Encoding.UTF8.GetString(res);
                string typeUBL22 = template.Replace("%TYPE%", typename);
                typeUBL22 = typeUBL22.Replace("%DATETIME%", DateTime.UtcNow.ToString());
                file2.WriteLine(typeUBL22);

                file2.Close();
            }

            StreamWriter file3 = new StreamWriter("c:\\temp\\" + "maintypes" + ".ts");
            foreach (string typename in namedtypes.Concat<string>(extranamedtypes))
            {
                var jsonStream = assembly.GetManifestResourceStream("ConvertUBLXsdToTsl.ubltsltemplate.txt");
                byte[] res = new byte[jsonStream.Length];
                int nBytes = jsonStream.Read(res);
                string template = Encoding.UTF8.GetString(res);
                string typeUBL22 = template.Replace("%TYPE%", typename);
                typeUBL22 = typeUBL22.Replace("%DATETIME%", DateTime.UtcNow.ToString());
                file3.WriteLine(typeUBL22);
            }
            file3.Close();

            Console.WriteLine("Press Enter to exit...");
            Console.ReadLine();
        }

        public static Dictionary<string,int> UniqueTypes = new Dictionary<string,int>();  

        private static void ProcessPropertyType(Dictionary<string, string> typepropertytypes, string type2, int level)
        {
            var typelist = typepropertytypes[type2];
            string[] types = typelist.Split(",");
            foreach(string typename in types)
            {
                string typename2 = typename.Replace("\"", "");
                if (typename2 != "string" && typename2 != "DateTime")
                {
                    if (!UniqueTypes.Keys.Contains(typename2))
                    {
                        UniqueTypes.Add(typename2, level);
                        Console.WriteLine(typename2 + "\t" + level.ToString());
                        ProcessPropertyType(typepropertytypes, typename2.Replace("Cac_", "") + "Type", level + 1);
                    }
                    else
                    {
                        Console.WriteLine(typename2 + " skipped");
                    }
                }
            }
        }
    }
}