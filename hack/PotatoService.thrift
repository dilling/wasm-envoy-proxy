namespace py potatoService

typedef string spud
service PotatoService {
    spud getSpud() ( 
        scope = "spud.read" 
    )
}
