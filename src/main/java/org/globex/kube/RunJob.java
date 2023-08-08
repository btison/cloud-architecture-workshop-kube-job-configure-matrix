package org.globex.kube;

import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.annotations.QuarkusMain;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.infrastructure.Infrastructure;
import jakarta.inject.Inject;

@QuarkusMain
public class RunJob implements QuarkusApplication {

    @Inject
    KubeRunner runner;

    @Override
    public int run(String... args) throws Exception {
        return Uni.createFrom().voidItem().emitOn(Infrastructure.getDefaultWorkerPool())
                .map(v -> runner.run()).await().indefinitely();
    }
}
