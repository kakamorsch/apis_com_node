const env = process.env.NODE_ENV || "dev";

const config = () => {
    switch(env) {
        case "dev":
        return{
            bdString: "mongodb+srv://morsch:905304@cluster0.rf0vi.gcp.mongodb.net/<dbname>?retryWrites=true&w=majority",
            jwtToken: "andar fome tempo menta",
            jwtExpiration: "7d"
        }
        
        case "hml":
        return {
            bdString: "mongodb+srv://morsch:905304@cluster0.rf0vi.gcp.mongodb.net/<dbname>?retryWrites=true&w=majority",
            jwtToken: "andar fome tempo menta",
            jwtExpiration: "1d"
        }

        case "prod":
        return {
            bdString: "mongodb+srv://morsch:905304@cluster0.rf0vi.gcp.mongodb.net/<dbname>?retryWrites=true&w=majority",
            jwtToken: "andar fome tempo menta",
            jwtExpiration: "1d"
        }
    }
}

console.log(`Iniciando a API em ambiente ${env.toUpperCase()}`)

module.exports = config();