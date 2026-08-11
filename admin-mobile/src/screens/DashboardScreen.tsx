import React from 'react';
import { ScrollView, StyleSheet, Text, TouchableOpacity, View } from 'react-native';
import { useAdminSession } from '../context/AdminSessionContext';
import { AccountLookup } from '../components/AccountLookup';
import { InviteCodes } from '../components/InviteCodes';
import { colors } from '../theme';

export function DashboardScreen() {
	const { session, logout } = useAdminSession();

	return (
		<ScrollView style={styles.flex} contentContainerStyle={styles.content}>
			<View style={styles.header}>
				<View>
					<Text style={styles.title}>Admin</Text>
					<Text style={styles.serviceUrl}>{session?.serviceUrl}</Text>
				</View>
				<TouchableOpacity onPress={logout}>
					<Text style={styles.signOut}>Sign out</Text>
				</TouchableOpacity>
			</View>

			<AccountLookup />
			<InviteCodes />
		</ScrollView>
	);
}

const styles = StyleSheet.create({
	flex: { flex: 1, backgroundColor: colors.background },
	content: { padding: 16, paddingTop: 24, paddingBottom: 48 },
	header: {
		flexDirection: 'row',
		justifyContent: 'space-between',
		alignItems: 'flex-start',
		marginBottom: 20
	},
	title: { fontSize: 22, fontWeight: '700', color: colors.text },
	serviceUrl: { fontSize: 12, color: colors.textMuted, marginTop: 2 },
	signOut: { fontSize: 13, color: colors.textMuted }
});
