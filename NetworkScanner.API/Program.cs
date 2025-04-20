// Program.cs
using NetworkScanner.API.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add CORS to allow React frontend to connect
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowReactApp", 
        builder => builder
            .WithOrigins("http://localhost:3000")
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials());
});

// Register our scanner service with logger support
builder.Services.AddScoped<NetworkScannerService>();
builder.Services.AddScoped<IpRangeService>();
builder.Services.AddLogging();

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("AllowReactApp");

app.MapControllers();

app.Run();