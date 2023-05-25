
using infraestructure.Model;
using infraestructure.Repository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata;
using System.Text;
using System.Threading.Tasks;

namespace Services.Services
{
    public  class PersonaService
    {
        private PersonaRepository personaRepository;
    public PersonaService(String connectionString)
    {
            this.personaRepository = new PersonaRepository(connectionString);

    }

    public string insertarPersona(PersonaModel persona)
    {
        return validadDatosPersona(persona) ? personaRepository.insertarPersona(persona) : throw new Exception("Error en la validacion") ;
    }


        public string modificarPersona(PersonaModel persona , int id )
        {
            return validadDatosPersona(persona) ? personaRepository.modificarPersona(persona , id) : throw new Exception("Error en la validacion");
        }


        public string eliminarPersona( int id)
        {

            return personaRepository.eliminarPersona(id);  
        }

        public IEnumerable<PersonaModel> listarPersona()
        {
            return personaRepository.listarPersona();
        }

        public PersonaModel consultarPersona(int id )
        {
            return personaRepository.consultarPersona(id);
        }


        private bool validadDatosPersona(PersonaModel persona)
    {
       // if(persona.Nombre.Trim().Length < 2)
       //    {
        //        return false;
       //     }
            return true;
        }
    }
}