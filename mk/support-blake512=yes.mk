CPPFLAGS_BLAKE512 = -DSUPPORT_BLAKE512

OBJ_BLAKE512 =\
	libblake_blake512_digest.o\
	libblake_blake512_digest_get_required_input_size.o\
	libblake_blake512_init.o\
	libblake_blake512_init2.o\
	libblake_blake512_update.o

OBJ_BLAKEB =\
	libblake_blake384_digest_get_required_input_size.o\
	libblake_internal_blakeb_digest.o\
	libblake_internal_blakeb_update.o
