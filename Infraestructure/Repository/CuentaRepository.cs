using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;
using Dapper;
using infraestructure.Model;

namespace infraestructure.Repository
{
    public class CuentaRepository
    {
        private string _connectionString;
        private Npgsql.NpgsqlConnection connection;

        public CuentaRepository(string connectionString)
        {
            this._connectionString = connectionString;  
            this.connection = new Npgsql.NpgsqlConnection(this._connectionString);
        }

        public string insertarCuenta(CuentaModel cuenta)
        {
            try { 
                connection.Execute("insert into cuenta( id , id_cuenta , nombre_cuenta , numero_cuenta , saldo , saldo_limite , " +
                    "limite_transferencia , estado ) " +
                "values (@Id ,@id_cuenta,  @nombre_cuenta , @numero_cuenta, @saldo ,@saldo_limite , @limite_transferencia , @estado)", 
                cuenta);
                return "Se inserto Correctamente";
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            
        }

        public string modificarCuenta(CuentaModel cuenta , int id)
        {
            try
            {
                _ = connection.Execute($" UPDATE cuenta set " +
                    "id_cuenta = @id_cuenta , " +
                    "nombre_cuenta = @nombre_cuenta , " +
                    "numero_cuenta = @numero_cuenta , " +
                    "saldo  = @saldo , " +
                    "saldo_limite = @saldo_limite , " +
                    "limite_transferencia = @limite_transferencia , " +
                    "estado= @estado " +
                    $"where id = {id}" , cuenta);

                return "Se modificaron los datos correctamente";
            }
            catch (Exception ex)
            {
                throw new Exception (ex.Message);
            }

        }

        public string eliminarCuenta(int id)
        {
            try
            {
                connection.Execute($" DELETE from cuenta " +
                    $"where id = {id}");
                return "Se elimino correctamente";
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }

        }


        public CuentaModel consultarCuenta(int id)
        {
            try
            {
                return  connection.QueryFirst<CuentaModel>($" select * from cuenta where id = {id}");
            }
            catch (Exception ex)
            {
                throw new Exception("No existe persona con el código ingresado!");
            }

        }

        public IEnumerable<CuentaModel> listarCuenta()
        {
            try
            {
                return connection.Query<CuentaModel>(" select * from cuenta order by id asc ");
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }

        }

    }
}
