/*******************************************************************************
 * Copyright (c) 2020 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package mpGraphQL10.jarInWar.inJar;

import java.util.ArrayList;
import java.util.List;

public class EntityInJarRefdFromWar {

    private static List<EntityInJarRefdFromWar> jars = new ArrayList<>();
    private String type;
    private LidTightness lidTightness;

    public static List<EntityInJarRefdFromWar> allJars() {
        return jars;
    }

    public EntityInJarRefdFromWar() {
    }

    public EntityInJarRefdFromWar(String type, LidTightness lidTightness) {
        this.type = type;
        this.lidTightness = lidTightness;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }
 
    public LidTightness getLidTightness() {
        return lidTightness;
    }

    public void setLidTightness(LidTightness lidTightness) {
        this.lidTightness = lidTightness;
    }
}
