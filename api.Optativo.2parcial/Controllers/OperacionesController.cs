using api.eavila.cuentas.Models;
using Microsoft.AspNetCore.Mvc;
using Services.Service;

namespace api.eavila.cuentas.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OperacionesController : Controller
    {
        private OperacionesServices operacionesService;

        private IConfiguration configuration;
        public OperacionesController(IConfiguration configuration)
        {
            this.configuration = configuration;
            this.operacionesService = new OperacionesServices(configuration.GetConnectionString("postgresDB"));

        }



        [HttpPut("depositar/{nro_cuenta}")]
        public ActionResult<string> depositar( double saldo , string nro_cuenta)
        {
         
                var resultado = this.operacionesService.depositar(saldo, nro_cuenta);

                return Ok(resultado);

        }

        [HttpPut("retirar/{nro_cuenta}")]
        public ActionResult<string> retirar(double saldo, string nro_cuenta)
        {

            var resultado = this.operacionesService.retirar(saldo, nro_cuenta);

            return Ok(resultado);


        }

        [HttpPut("transferir/{nro_cuenta_envio}/{nro_cuenta_recibe}")]
        public ActionResult<string> transferir(string nro_cuenta_envio, string nro_cuenta_recibe, double monto)
        {

            var resultado = this.operacionesService.transferir(nro_cuenta_envio, nro_cuenta_recibe, monto);

            return Ok(resultado);
             

        }

        [HttpPut("bloquear/{nro_cuenta}")]
        public ActionResult<string> bloquear(string nro_cuenta)
        {

            var resultado = this.operacionesService.bloquear(nro_cuenta);

            return Ok(resultado);


        }

        [HttpGet("extracto/{nro_cuenta}")]
        public ActionResult<List<ExtractoModel>> ImprimirExtracto(string nro_cuenta)
        {
            var resultado = operacionesService.listarExtracto(nro_cuenta);
            return Ok(resultado);
        }

    }
}
