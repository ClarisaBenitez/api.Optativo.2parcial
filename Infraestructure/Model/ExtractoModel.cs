using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace infraestructure.Model
{
    public class ExtractoModel
    {
        public int id { get; set; }

        public string fecha { get; set; }
        public string operacion { get; set; }

        public string observacion { get; set; }

        public double importe { get; set; }

        public string estado { get; set; }

        public string nro_cuenta { get; set; }

    }
}
