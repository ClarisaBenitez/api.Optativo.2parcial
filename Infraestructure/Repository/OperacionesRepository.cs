using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection.Metadata;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Dapper;
using infraestructure.Model;

namespace infraestructure.Repository
{
    public class OperacionesRepository
    {
        private string _connectionString;
        private Npgsql.NpgsqlConnection connection;

        public OperacionesRepository(string connectionString)
        {
            this._connectionString = connectionString;  
            this.connection = new Npgsql.NpgsqlConnection(this._connectionString);
        }


        public string depositar(double saldo ,  string nroCuenta)
        {
            try
            {
             
             
                var valorSaldoAnterior = saldoActual(nroCuenta);
                var valorSaldoLimite = saldoLimite(nroCuenta);
                var valorDepositado = saldo;
                var valorNuevo = valorSaldoAnterior + valorDepositado;


                if (valorNuevo <= valorSaldoLimite)
                {
                    _ = connection.Execute($" UPDATE cuenta set " +
                   $"saldo = {valorNuevo}  " +
                   $"where numero_cuenta = '{nroCuenta}'");

                    insertarExtracto(saldo, "DEPOSITO", "Desposito Realizado", nroCuenta);


                    return "Deposito realizado correctamente";
                }
                else
                    return "El valor depositado supera el saldo limite de la cuenta!";
            }
            catch (Exception ex)
            {
                throw new Exception (ex.Message); 

            }
        }


        public string retirar(double valorRetirado, string nroCuenta)
        {
            try
            { 
                var valorSaldoActual = saldoActual(nroCuenta);
                var valoraRetirar = valorRetirado;



                if (valoraRetirar <= valorSaldoActual)
                {
                    var valorNuevo = valorSaldoActual - valoraRetirar ;

                    _ = connection.Execute($" UPDATE cuenta set " +
                   $"saldo = {valorNuevo}  " +
                   $"where numero_cuenta = '{nroCuenta}'");


                    insertarExtracto(valorRetirado, "RETIRO", "Retiro Realizado", nroCuenta);

                    return "Retiro realizado correctamente";
                }
                else
                    return "No tiene saldo suficiente para realizar el retiro!";
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }
         
        public string transferir (string nroCuenta_envio, string nroCuenta_recibe, double monto)
        {

            if (nroCuenta_envio != nroCuenta_recibe)
            {
                var valorBloq = "Bloqueado";
                var valorBloqEnvio = cuentaBloqueada(nroCuenta_envio);
                var valorBloqRecibe = cuentaBloqueada(nroCuenta_recibe);

                if(valorBloqEnvio == valorBloq || valorBloqRecibe == valorBloq ) { 

                   
                return "No es posible realizar la transferencia con cuentas Bloqueadas"; 
            }else
                {
                    var saldo_envia = saldoActual(nroCuenta_envio);
                    var limite_envio = saldoLimiteEnvio(nroCuenta_envio);

                    var saldo_recibe = saldoActual(nroCuenta_recibe);
                    var limite_recibe = saldoLimite(nroCuenta_recibe);

                    if (saldo_envia >= monto && limite_envio >= monto)
                    {

                        envio(monto, nroCuenta_recibe);
                        debitar(monto, nroCuenta_envio);

                        insertarExtracto(monto, "TRANSFERENCIA", "Transferencia realizada a la cuenta:  " + nroCuenta_recibe + " ", nroCuenta_envio);

                        return "Transferencia realizada correctamente";

                    }
                    return "No es posible realizar la transferencia";
                }
            }

            return "No se puede realizar el deposito a la misma cuenta";
        }


        public double saldoActual(string nroCuenta)
        {
            return connection.QuerySingle<double>($" select saldo from cuenta where numero_cuenta = '{nroCuenta}'");
        }
        public double saldoLimite(string nroCuenta)
        {
            return connection.QuerySingle<double>($" select saldo_limite from cuenta where numero_cuenta = '{nroCuenta}'");
        }
        public double saldoLimiteEnvio(string nroCuenta)
        {
            return connection.QuerySingle<double>($" select limite_transferencia from cuenta where numero_cuenta = '{nroCuenta}'");
        }

        public string cuentaBloqueada(string nroCuenta)
        {
            return connection.QuerySingle<string>($" select estado from cuenta where numero_cuenta = '{nroCuenta}'");
        }

        public void envio(double valorRetirado, string nroCuenta)
        {
            try
            { 
                var valorSaldoActual = saldoActual(nroCuenta);
                var valorSaldoLimiteEnvio = saldoLimiteEnvio(nroCuenta);
                var valoraRetirar = valorRetirado;
                                
                var valorNuevo = valorSaldoActual + valoraRetirar;

                if(valorSaldoLimiteEnvio >= valoraRetirar) {
                    _ = connection.Execute($" UPDATE cuenta set " +
                   $"saldo = {valorNuevo}  " +
                   $"where numero_cuenta = '{nroCuenta}'");
                }
            }

            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }


    public void debitar(double valorRetirado, string nroCuenta)
    {
        try
        {
            var valorSaldoActual = saldoActual(nroCuenta);
            var valoraRetirar = valorRetirado;

                var valorNuevo = valorSaldoActual - valoraRetirar;
                if(valorSaldoActual >= valoraRetirar)
                {
                    _ = connection.Execute($" UPDATE cuenta set " +
                   $"saldo = {valorNuevo}  " +
                   $"where numero_cuenta = '{nroCuenta}'");
                }

            
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
        }

        public string bloquear(string nroCuenta) 
        {
            try
            {
                _ = connection.Execute($" UPDATE cuenta set " +
                   $"estado = 'Bloqueado' " +
                   $"where numero_cuenta = '{nroCuenta}'");


                insertarExtracto(0, "BLOQUEO", "Cuenta bloqueada" , nroCuenta);
                return "Cuenta Bloqueada correctamente";
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }


        public void insertarExtracto( double monto ,string operacion , string observacion , string nro_cuenta)
        {
            try
            {
                
                string fecha = DateTime.Now.ToString();
               
                string fecha_formateada = String.Format("{0:MM/dd/yyyy}", fecha);

                connection.Execute("insert into extracto( fecha , operacion , observacion , importe , estado , nro_cuenta ) " +
                $"values ( '{fecha_formateada}' , '{operacion}' ,'{observacion}' , {monto}, 'Procesado' ,'{nro_cuenta}'   )") ;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);

            }

        }

        public IEnumerable<ExtractoModel> listarExtracto(string nroCuenta)
        {
            try
            {
                return connection.Query<ExtractoModel>(" select id, CAST(fecha AS character varying ) as fecha , operacion , observacion, importe ,estado ,nro_cuenta from extracto where nro_cuenta = '" + nroCuenta + "' ");
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }

        }
    }
}
