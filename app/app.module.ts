import { NativeScriptModule } from "nativescript-angular/platform";
import { NgModule } from "@angular/core";
import { NativeScriptRouterModule } from "nativescript-angular/router";
import { authProviders, appRoutes } from "./app.routing";
import { AppComponent } from './app.component';

@NgModule({
    imports: [
        NativeScriptModule,
        NativeScriptRouterModule,
        NativeScriptRouterModule.forRoot(appRoutes)
    ],
    declarations: [AppComponent],
    providers: [ 
        authProviders
    ],
    bootstrap: [AppComponent],
})
export class AppModule { }
