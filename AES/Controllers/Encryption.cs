using AES.AES;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AES.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class Encryption : ControllerBase
    {
        private readonly Encrypt encrypt;

        public Encryption(Encrypt encrypt)
        {
            this.encrypt = encrypt;
        }

        [HttpPost("ecrpty")]
        public IActionResult encrpyt([FromQuery] string text)
        {
            try
            {
                var response = encrypt.EncryptAES(text);
                return StatusCode(200, response);

            }
            catch(Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }

        [HttpPost("ecrpty-native")]
        public IActionResult encrpytNew([FromQuery] string text)
        {
            try
            {
                var response = encrypt.EncryptAESNative(text);
                return StatusCode(200, response);

            }
            catch (Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }






        [HttpPost("decrpty")]
        public IActionResult dencrpyt([FromQuery] string text)
        {
            try
            {
                var response = encrypt.DecryptAES(text);
                return StatusCode(200, response);

            }
            catch (Exception ex)
            {
                return StatusCode(400, ex.Message);
            }
        }


    }
}
