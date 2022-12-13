﻿Функция ЗагрузиСоответствиеТочекПродажПодразделениям() Экспорт
	
		Запрос = Новый Запрос();
		Запрос.Текст = 
		"ВЫБРАТЬ
		|	ТочкиПродажВподразделения.Точка КАК Точка,
		|	ТочкиПродажВподразделения.Подразделение КАК Подразделение,
		|	ТочкиПродажВподразделения.ДопРеквизитАдресации КАК ДопРеквизитАдресации
		|ИЗ
		|	РегистрСведений.ТочкиПродажВподразделения КАК ТочкиПродажВподразделения";
		РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
		Выборка = РезультатЗапроса.Выбрать();
		Пока Выборка.Следующий() Цикл
			Новая = ЭтотОбъект.ТочкиПродажиВПодразделения.Добавить();
			Новая.ТочкаПродажи  		= Выборка.Точка;
			Новая.Подразделение 		= Выборка.Подразделение;
			Новая.ДопРеквизитАдресации  = Выборка.ДопРеквизитАдресации;
		КонецЦикла;
		
КонецФункции