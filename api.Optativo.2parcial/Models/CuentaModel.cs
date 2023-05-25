namespace api.eavila.cuentas.Models
{
    public class CuentaModel
    {
        public int id { get; set; }

        public int id_cuenta { get; set; }
        public string nombre_cuenta { get; set; }

        public string numero_cuenta { get; set; }

        public double saldo { get; set; }

        public double saldo_limite { get; set; }

        public double limite_transferencia { get; set; }

        public string estado { get; set; }

    }
}