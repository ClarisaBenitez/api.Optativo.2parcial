using api.eavila.cuentas.Models;
using Microsoft.AspNetCore.Mvc;
using Services.Service;
using Services.Services;
using System.Reflection;


namespace api.eavila.cuentas.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CuentasController : ControllerBase
    {

        private CuentaServices cuentaService;

        private IConfiguration configuration;
        public CuentasController(IConfiguration configuration)
        {
            this.configuration = configuration;
            this.cuentaService = new CuentaServices(configuration.GetConnectionString("postgresDB"));

        }

        [HttpGet("ListarCuentas")]
        public ActionResult<List<CuentaModel>> ListarCuentas()
        {
            var resultado = cuentaService.listarCuentas();
            return Ok(resultado);
        }

        [HttpGet("ConsultarCuenta/{id}")]
        public ActionResult<CuentaModel> ConsultarCuenta(int id)
        {
            var resultado = cuentaService.consultarCuenta(id);
            return Ok(resultado);
        }

        [HttpPost("InsertarCuenta")]
        public ActionResult<string> insertarCuenta(CuentaModel modelo)
        {
            var resultado = this.cuentaService.insertarCuenta(new infraestructure.Model.CuentaModel
            {
        id = modelo.id,
        id_cuenta = modelo.id_cuenta,
        nombre_cuenta = modelo.nombre_cuenta,
        numero_cuenta = modelo.numero_cuenta,
        saldo = modelo.saldo,
        saldo_limite = modelo.saldo_limite,
        limite_transferencia = modelo.limite_transferencia,
        estado = modelo.estado

    });
            return Ok(resultado);
        }

        [HttpPut("ModificarCuenta/{id}")]
        public ActionResult<string> modificarCuenta(CuentaModel modelo, int id)
        {
            if (cuentaService.consultarCuenta(id) != null)
            {
                var resultado = this.cuentaService.modificarCuenta(new infraestructure.Model.CuentaModel
                {
                    id_cuenta = modelo.id_cuenta,
                    nombre_cuenta = modelo.nombre_cuenta,
                    numero_cuenta = modelo.numero_cuenta,
                    saldo = modelo.saldo,
                    saldo_limite = modelo.saldo_limite,
                    limite_transferencia = modelo.limite_transferencia,
                    estado = modelo.estado

                }, id);

                return Ok(resultado);
            }
            else
                return NotFound("Cuenta no Existe!");

        }

        [HttpDelete("EliminarCuenta/{id}")]
        public ActionResult<string> eliminarCuenta(int id)
        {
            var resultado = this.cuentaService.eliminarCuenta(id);
            return Ok(resultado);
        }

    }
}
