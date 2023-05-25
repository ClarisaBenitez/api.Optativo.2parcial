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
    public class PersonaRepository
    {
        private string _connectionString;
        private Npgsql.NpgsqlConnection connection;

        public PersonaRepository(string connectionString)
        {
            this._connectionString = connectionString;  
            this.connection = new Npgsql.NpgsqlConnection(this._connectionString);
        }

        public string insertarPersona(PersonaModel persona)
        {
            try { 
                connection.Execute("insert into persona(id , nombre, apellido , edad , email , telefono) " +
                "values (@id , @nombre, @apellido , @edad , @email , @telefono)", persona);
                return "Se inserto Correctamente";
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            
        }

        public string modificarPersona(PersonaModel persona , int id)
        {
            try
            {
                _ = connection.Execute($" UPDATE persona set " +
                    "nombre = @nombre , " +
                    "apellido = @apellido , " +
                    "edad = @edad , " +
                    "email  = @email , " +
                    "telefono = @telefono " +
                    $"where id = {id}" , persona);

                return "Se modificaron los datos correctamente";
            }
            catch (Exception ex)
            {
                throw new Exception (ex.Message);
            }

        }

        public string eliminarPersona(int id)
        {
            try
            {
                connection.Execute($" DELETE from persona " +
                    $"where id = {id}");
                return "Se elimino correctamente";
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }

        }

        public PersonaModel consultarPersona(int id)
        {
            try
            {
                return  connection.QueryFirst<PersonaModel>($" select * from persona where id = {id}");
            }
            catch (Exception ex)
            {
                throw new Exception("No existe persona con el código ingresado!");
            }

        }

        public IEnumerable<PersonaModel> listarPersona()
        {
            try
            {
                return connection.Query<PersonaModel>(" select * from persona order by id asc ");
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }

        }

    }
}
