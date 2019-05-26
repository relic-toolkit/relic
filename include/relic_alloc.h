


#ifdef _MSC_VER
    #include <malloc.h>

    // Dynamiclly allocates an array of "Type" with the specified size on the stack. 
    // This memory will be automaticlly deallocated from the stack when the function 
    // frame is returned from.
    //
    // Note: This is the Windows specific implementation.
    #define RLC_ALLOCA(Type, size)(Type*) _alloca((size) * sizeof(Type))
#else

    #include <alloca.h>

    // Dynamiclly allocates an array of "Type" with the specified size on the stack. 
    // This memory will be automaticlly deallocated from the stack when the function 
    // frame is returned from. 
    //
    // Note: This is the POSIX specific implementation.
    #define RLC_ALLOCA(Type, size)(Type*) alloca((size) * sizeof(Type))
#endif
