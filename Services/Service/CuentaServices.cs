using infraestructure.Model;
using infraestructure.Repository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Services.Service
{
    public class CuentaServices
    {

        private CuentaRepository cuentaRepository;

        public CuentaServices(String connectionString)
        {
            this.cuentaRepository = new CuentaRepository(connectionString);
        }

        public string insertarCuenta(CuentaModel cuenta)
        {
            return validarDatosCuenta (cuenta) ? cuentaRepository.insertarCuenta(cuenta) : throw new Exception("Error en la validacion");

        }

        public string modificarCuenta(CuentaModel cuenta , int id )
        {
            return validarDatosCuenta(cuenta) ? cuentaRepository.modificarCuenta(cuenta , id) :  throw new Exception("Error en la validacion");
        }

        public string eliminarCuenta(int id )
        {
            return cuentaRepository.eliminarCuenta(id); ;
        }

        public CuentaModel consultarCuenta(int id )
        {
            return cuentaRepository.consultarCuenta(id);
        }

        public IEnumerable<CuentaModel> listarCuentas()
        {
            return cuentaRepository.listarCuenta(); ;
        }

        private bool validarDatosCuenta(CuentaModel cuenta)
        {
            // if(persona.Nombre.Trim().Length < 2)
            //    {
            //        return false;
            //     }
            return true;
        }
    }

}

