using infraestructure.Model;
using infraestructure.Repository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Services.Service
{
    public class OperacionesServices
    {

        private OperacionesRepository operacionesRepository;
        private CuentaRepository cuentaRepository;


        public OperacionesServices(String connectionString)
        {
            this.operacionesRepository = new OperacionesRepository(connectionString);
            this.cuentaRepository = new CuentaRepository(connectionString);
        }

     


        public string transferir(string nro_cuenta_envio, string nro_cuent_recibe, double monto)
        {
            return validarNegativo(monto) ? operacionesRepository.transferir(nro_cuenta_envio, nro_cuent_recibe,  monto) : throw new Exception("No se puede depositar un valor negativo");
        }

        public string depositar(double saldo, string nro_cuenta)
        {
            return validarNegativo(saldo) ? operacionesRepository.depositar(saldo, nro_cuenta) : throw new Exception("No se puede depositar un valor negativo");
        }


        public string retirar(double saldo, string nro_cuenta)
        {
            return validarNegativo(saldo) ? operacionesRepository.retirar(saldo, nro_cuenta) : throw new Exception("No se puede depositar un valor negativo");
        }

        public string bloquear(string nro_cuenta)
        {
            return operacionesRepository.bloquear(nro_cuenta);
        }

        public IEnumerable<ExtractoModel> listarExtracto(string nro_cuenta)
        {
            return operacionesRepository.listarExtracto(nro_cuenta); 
        }

        private bool validarNegativo( double saldo )
        {
            if(saldo < 0)
            {
            return false;
            }
            return true;
        }

    }
}
