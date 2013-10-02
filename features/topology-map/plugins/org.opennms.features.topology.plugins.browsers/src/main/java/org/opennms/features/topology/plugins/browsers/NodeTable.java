/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2013 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2013 The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * OpenNMS(R) is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OpenNMS(R).  If not, see:
 *      http://www.gnu.org/licenses/
 *
 * For more information contact:
 *     OpenNMS(R) Licensing <license@opennms.org>
 *     http://www.opennms.org/
 *     http://www.opennms.com/
 *******************************************************************************/

package org.opennms.features.topology.plugins.browsers;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import org.apache.commons.lang.ArrayUtils;
import org.opennms.core.criteria.Order;
import org.opennms.core.utils.InetAddressComparator;
import org.opennms.netmgt.model.OnmsNode;
import org.opennms.osgi.EventProxy;
import org.opennms.osgi.EventProxyAware;
import org.slf4j.LoggerFactory;

import com.vaadin.ui.Table;

@SuppressWarnings("serial")
public class NodeTable extends SelectionAwareTable {

    private EventProxy eventProxy;

	@SuppressWarnings("unchecked") // Because Aries Blueprint cannot handle generics
	public NodeTable(String caption, NodeDaoContainer container) {
		super(caption, container);
	}
}