using Microsoft.AspNetCore.Mvc;

namespace AuthNET.Controllers;

[ApiController]
[Route("authenticate")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;

    public AuthController(ILogger<AuthController> logger)
    {
        _logger = logger;
    }


    [HttpGet]
    public Task<ActionResult> Authenticate()
    {
        return Task.FromResult<ActionResult>(Ok(new { message = "Authenticated" }));
    }
}
