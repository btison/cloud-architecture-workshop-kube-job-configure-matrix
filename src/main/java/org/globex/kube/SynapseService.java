package org.globex.kube;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

@RegisterRestClient(configKey="synapse")
@Path("/_synapse/admin")
public interface SynapseService {

    @GET
    @Path("/v1/register")
    @Produces(MediaType.APPLICATION_JSON)
    Response register();

    @POST
    @Path("/v1/register")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    Response registerUser(String payload);

    @PUT
    @Path("v2/users/{userId}")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    Response createUser(String payload, @PathParam("userId") String userId, @HeaderParam("Authorization") String bearerToken);

}
